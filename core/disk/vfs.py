import os
import os.path
from hashlib import sha1
from pathlib import Path

from samokoder.core.disk.ignore import IgnoreMatcher
from samokoder.core.log import get_logger

log = get_logger(__name__)


class VirtualFileSystem:
    def save(self, path: str, content: str):
        """
        Save content to a file. Use for both new and updated files.

        :param path: Path to the file, relative to project root.
        :param content: Content to save.
        """
        raise NotImplementedError()

    def read(self, path: str) -> str:
        """
        Read file contents.

        :param path: Path to the file, relative to project root.
        :return: File contents.
        """
        raise NotImplementedError()

    def remove(self, path: str):
        """
        Remove a file.

        If file doesn't exist or is a directory, or if the file is ignored,
        do nothing.

        :param path: Path to the file, relative to project root.
        """
        raise NotImplementedError()

    def get_full_path(self, path: str) -> str:
        """
        Get the full path to a file.

        This should be used to check the full path of the file on whichever
        file system it locally is stored. For example, getting a full path
        to a file and then passing it to an external program via run_command
        should work.

        :param path: Path to the file, relative to project root.
        :return: Full path to the file.
        """
        raise NotImplementedError()

    def _filter_by_prefix(self, file_list: list[str], prefix: str) -> list[str]:
        # We use "/" internally on all platforms, including win32
        if not prefix.endswith("/"):
            prefix = prefix + "/"
        return [f for f in file_list if f.startswith(prefix)]

    def _get_file_list(self) -> list[str]:
        raise NotImplementedError()

    def list(self, prefix: str = None) -> list[str]:
        """
        Return a list of files in the project.

        File paths are relative to the project root.

        :param prefix: Optional prefix to filter files for.
        :return: List of file paths.
        """
        retval = sorted(self._get_file_list())
        if prefix:
            retval = self._filter_by_prefix(retval, prefix)
        return retval

    def hash(self, path: str) -> str:
        content = self.read(path)
        return self.hash_string(content)

    @staticmethod
    def hash_string(content: str) -> str:
        return sha1(content.encode("utf-8")).hexdigest()


class MemoryVFS(VirtualFileSystem):
    files: dict[str, str]

    def __init__(self):
        self.files = {}

    def save(self, path: str, content: str):
        self.files[path] = content

    def read(self, path: str) -> str:
        try:
            return self.files[path]
        except KeyError:
            raise ValueError(f"File not found: {path}")

    def remove(self, path: str):
        if path in self.files:
            del self.files[path]

    def get_full_path(self, path: str) -> str:
        # We use "/" internally on all platforms, including win32
        return "/" + path

    def _get_file_list(self) -> list[str]:
        return self.files.keys()


class LocalDiskVFS(VirtualFileSystem):
    """
    A virtual file system implementation that stores files on the local disk.

    SECURITY WARNING:
    This implementation is NOT SANDBOXED. The agent has direct file system
    access within the specified `root` directory. A malicious or buggy agent
    could potentially perform harmful actions such as path traversal attacks (`../`),
    accessing sensitive files, or exhausting disk space. 

    For a production environment, it is STRONGLY RECOMMENDED to replace this
    with a sandboxed implementation. The ideal solution involves running the
    agent's processes (and by extension, all file operations) inside a
    secure, isolated container (e.g., using Docker). The ProcessManager would
    need to be updated to execute commands within this container, and the VFS
    would interact with the container's isolated file system.
    """
    def __init__(
        self,
        root: str,
        create: bool = True,
        allow_existing: bool = True,
        ignore_matcher: IgnoreMatcher = None,
    ):
        if not os.path.isdir(root):
            if create:
                os.makedirs(root)
            else:
                raise ValueError(f"Root directory does not exist: {root}")
        else:
            if not allow_existing:
                raise FileExistsError(f"Root directory already exists: {root}")

        if ignore_matcher is None:
            ignore_matcher = IgnoreMatcher(root, [])

        self.root = root
        self.ignore_matcher = ignore_matcher

    def get_full_path(self, path: str) -> str:
        return os.path.abspath(os.path.normpath(os.path.join(self.root, path)))

    def save(self, path: str, content: str):
        full_path = self.get_full_path(path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
        log.debug(f"Saved file {path} ({len(content)} bytes) to {full_path}")

    def read(self, path: str) -> str:
        full_path = self.get_full_path(path)
        if not os.path.isfile(full_path):
            raise ValueError(f"File not found: {path}")

        # TODO: do we want error handling here?
        with open(full_path, "r", encoding="utf-8") as f:
            return f.read()

    def remove(self, path: str):
        if self.ignore_matcher.ignore(path):
            return

        full_path = self.get_full_path(path)
        if os.path.isfile(full_path):
            try:
                os.remove(full_path)
                log.debug(f"Removed file {path} from {full_path}")
            except Exception as err:  # noqa
                log.error(f"Failed to remove file {path}: {err}", exc_info=True)

    def _get_file_list(self) -> list[str]:
        files = []
        for dpath, dirnames, filenames in os.walk(self.root):
            # Modify in place to prevent recursing into ignored directories
            dirnames[:] = [
                d
                for d in dirnames
                if not self.ignore_matcher.ignore(os.path.relpath(os.path.join(dpath, d), self.root))
            ]

            for filename in filenames:
                path = os.path.relpath(os.path.join(dpath, filename), self.root)
                if not self.ignore_matcher.ignore(path):
                    # We use "/" internally on all platforms, including win32
                    files.append(Path(path).as_posix())

        return files


import docker
import tarfile
import io
from datetime import datetime

class DockerVFS(VirtualFileSystem):
    """
    A virtual file system implementation that interacts with a Docker container.
    This provides a basic level of sandboxing by isolating file operations
    and command execution within a container.
    """

    def __init__(self, container_name: str):
        self.container_name = container_name
        self.client = docker.from_env()
        
        try:
            # Check if the container already exists
            self.container = self.client.containers.get(container_name)
            if self.container.status != "running":
                log.info(f"Container '{container_name}' exists but is not running. Starting it...")
                self.container.start()
            else:
                log.info(f"Attached to existing running container '{container_name}'.")

        except docker.errors.NotFound:
            log.info(f"Container '{container_name}' not found. Creating a new one...")
            try:
                self.container = self.client.containers.run(
            "samokoder-execution:latest",
            "--rm",
            "-v",
            f"{self.root}:/workspace",
            "--network=host",
            "--add-host=host.docker.internal:host-gateway",
            labels={"managed-by": "samokoder"},
        )
        if not image:
            log.error("The 'samokoder-execution:latest' image was not found.")
                raise ValueError("Execution environment image not found. Please build it using 'docker-compose build execution-environment'")
        except Exception as e:
            log.error(f"An unexpected error occurred with Docker: {e}")
            raise

    async def cleanup(self):
        """Stops and removes the container managed by this VFS."""
        if self.container:
            try:
                log.info(f"Stopping and removing container '{self.container_name}'...")
                self.container.stop()
                self.container.remove()
                log.info(f"Successfully cleaned up container '{self.container_name}'.")
            except Exception as e:
                log.error(f"Failed to clean up container '{self.container_name}': {e}")

    def save(self, path: str, content: str):
        # In-memory tar archive creation
        pw_tarstream = io.BytesIO()
        pw_tar = tarfile.TarFile(fileobj=pw_tarstream, mode='w')
        
        file_data = content.encode('utf-8')
        tarinfo = tarfile.TarInfo(name=path)
        tarinfo.size = len(file_data)
        
        pw_tar.addfile(tarinfo, io.BytesIO(file_data))
        pw_tar.close()
        pw_tarstream.seek(0)

        self.container.put_archive(path=os.path.dirname(f"/workspace/{path}"), data=pw_tarstream)
        log.debug(f"Saved file {path} to container {self.container_name}")

    def read(self, path: str) -> str:
        try:
            bits, stat = self.container.get_archive(f"/workspace/{path}")
            
            file_obj = io.BytesIO()
            for chunk in bits:
                file_obj.write(chunk)
            file_obj.seek(0)
            
            with tarfile.open(fileobj=file_obj) as tar:
                # Get the first file in the archive (should be the only one)
                member = tar.getmembers()[0]
                extracted_file = tar.extractfile(member)
                if extracted_file:
                    return extracted_file.read().decode('utf-8')
            return ""
        except docker.errors.NotFound:
            raise ValueError(f"File not found in container: {path}")

    def remove(self, path: str):
        try:
            self.container.exec_run(f"rm /workspace/{path}")
            log.debug(f"Removed file {path} from container {self.container_name}")
        except Exception as e:
            log.error(f"Failed to remove file {path} from container: {e}", exc_info=True)

    def get_full_path(self, path: str) -> str:
        return f"/workspace/{path}"

    def _get_file_list(self) -> list[str]:
        exit_code, output = self.container.exec_run(["find", ".", "-type", "f"])
        if exit_code != 0:
            log.warning(f"Error listing files in container: {output.decode('utf-8')}")
            return []
        
        files = output.decode('utf-8').splitlines()
        # Remove the leading './' from the paths
        return [f[2:] for f in files if f.startswith('./')]


__all__ = ["VirtualFileSystem", "MemoryVFS", "LocalDiskVFS", "DockerVFS"]

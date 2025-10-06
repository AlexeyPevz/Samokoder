from samokoder.core.db.models import Branch, Project, ProjectState, User


def create_project_state(user: User, project_name="Test Project", branch_name=Branch.DEFAULT):
    """
    Create a test Project, Branch, Specification and ProjectState objects.

    The objects are created as transient objects, so they need to be added
    to a session before committing and saving them to the database.

    :param project_name: The project name.
    :param branch_name: The branch name.
    :param user: The User object.
    :return: The ProjectState object.
    """

    project = Project(name=project_name, user_id=user.id)
    branch = Branch(name=branch_name, project=project)
    return ProjectState.create_initial_state(branch)

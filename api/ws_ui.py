import asyncio
import json
from typing import Dict, Any

from samokoder.core.ui.base import UIBase, UserInput

class WebSocketUI(UIBase):
    """UI implementation that sends messages via WebSocket"""

    def __init__(self, websocket, user_id: str):
        self.websocket = websocket
        self.user_id = user_id
        self.project_root = None
        self.message_queue = asyncio.Queue()
        self.pending_question = None

    async def start(self) -> bool:
        # Start a background task to receive messages
        asyncio.create_task(self._message_receiver())
        return True

    async def stop(self):
        pass

    async def _message_receiver(self):
        """Receives messages from the websocket and puts them in a queue."""
        try:
            while True:
                message = await self.websocket.receive_text()
                await self.message_queue.put(message)
        except Exception as e:
            # Handle disconnection or errors
            await self.message_queue.put(None)  # Signal end of messages

    async def send_message(self, message: str, *, source=None, **kwargs):
        await self.websocket.send_text(json.dumps({
            "type": "message",
            "content": message,
            "source": source
        }))

    async def send_project_stage(self, stage: Dict[str, Any]):
        await self.websocket.send_text(json.dumps({
            "type": "project_stage",
            "stage": stage
        }))

    async def send_stream_chunk(self, chunk: str, *, source=None, **kwargs):
        if not chunk:
            return
        await self.websocket.send_text(json.dumps({
            "type": "process_output",
            "data": chunk
        }))

    async def send_process_status(self, status_code: int):
        await self.websocket.send_text(json.dumps({
            "type": "process_status",
            "status_code": status_code
        }))

    async def ask_question(
        self,
        question: str,
        *,
        buttons=None,
        default=None,
        allow_empty=False,
        source=None,
        full_screen=False,
        buttons_only=False,
    ) -> UserInput:
        # Send question to frontend
        await self.websocket.send_text(json.dumps({
            "type": "question",
            "question": question,
            "buttons": buttons,
            "default": default,
            "allow_empty": allow_empty,
            "source": source,
            "full_screen": full_screen,
            "buttons_only": buttons_only
        }))

        # Wait for a response of type 'answer' from the queue
        while True:
            try:
                response_text = await asyncio.wait_for(self.message_queue.get(), timeout=300.0)  # 5 minutes timeout
                if response_text is None:
                    return UserInput(cancelled=True)

                data = json.loads(response_text)

                if data.get("type") == "answer":
                    return UserInput(
                        text=data.get("text", ""),
                        button=data.get("button"),
                        cancelled=data.get("cancelled", False)
                    )
                else:
                    # If the message is not an answer, put it back in the queue for another handler
                    # (e.g., a chat command handler) and continue waiting.
                    await self.message_queue.put(response_text)
            except asyncio.TimeoutError:
                # If no response within timeout, return cancelled
                return UserInput(cancelled=True)
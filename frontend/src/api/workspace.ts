class WorkspaceSocket {
    private socket: WebSocket | null = null;
    private onMessageCallback: ((message: any) => void) | null = null;

    connect(projectId: string, onMessage: (message: any) => void) {
        this.onMessageCallback = onMessage;
        const token = localStorage.getItem('accessToken');
        const protocol = window.location.protocol === 'https' ? 'wss' : 'ws';
        const host = window.location.host;
        this.socket = new WebSocket(`${protocol}://${host}/api/v1/ws/${projectId}?token=${token}`);

        this.socket.onopen = () => {
            console.log('WebSocket connection established');
        };

        this.socket.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                if (this.onMessageCallback) {
                    this.onMessageCallback(message);
                }
            } catch (e) {
                console.error('Error parsing WebSocket message:', e);
            }
        };

        this.socket.onclose = () => {
            console.log('WebSocket connection closed');
        };

        this.socket.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    sendMessage(message: string) {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            // Send message in the format expected by the backend
            this.socket.send(message);
        } else {
            console.error('WebSocket is not connected');
        }
    }

    disconnect() {
        if (this.socket) {
            this.socket.close();
        }
    }
}

export const workspaceSocket = new WorkspaceSocket();

"""Quick-start script for NetSentinel backend."""
import os
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "netsentinel.main:app",
        host="0.0.0.0",
        port=int(os.getenv("NETSENTINEL_PORT", "8100")),
        reload=False,  # Disabled to prevent WebSocket disconnects
        log_level="info",
    )

import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";
import { installGlobalErrorHandlers } from "./api/telemetry";

// Install frontend error telemetry (fire-and-forget)
installGlobalErrorHandlers();

createRoot(document.getElementById("root")!).render(<App />);

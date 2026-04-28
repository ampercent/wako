interface StatusIndicatorProps {
  isLive: boolean;
}

export default function StatusIndicator({ isLive }: StatusIndicatorProps) {
  return (
    <div className="flex items-center gap-2">
      <div className="relative flex h-2.5 w-2.5">
        <span
          className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-75 ${isLive ? "bg-success" : "bg-warning"
            }`}
        />
        <span
          className={`relative inline-flex h-2.5 w-2.5 rounded-full ${isLive ? "bg-success" : "bg-warning"
            }`}
        />
      </div>
      <span className="font-mono text-xs text-muted-foreground">
        {isLive ? "LIVE" : "OFFLINE"}
      </span>
    </div>
  );
}

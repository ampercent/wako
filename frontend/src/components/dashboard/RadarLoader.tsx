export default function RadarLoader({ label = "Scanning..." }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-12">
      <div className="relative h-16 w-16">
        {/* Outer ring */}
        <div className="absolute inset-0 rounded-full border-2 border-primary/20" />
        {/* Sweep line */}
        <div className="absolute inset-0 animate-radar">
          <div
            className="h-8 w-0.5 origin-bottom rounded-full"
            style={{
              position: "absolute",
              top: 0,
              left: "50%",
              transform: "translateX(-50%)",
              background: "linear-gradient(to top, hsl(var(--primary)), transparent)",
            }}
          />
        </div>
        {/* Center dot */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="h-2 w-2 rounded-full bg-primary glow-primary" />
        </div>
        {/* Inner rings */}
        <div className="absolute inset-2 rounded-full border border-primary/10" />
        <div className="absolute inset-4 rounded-full border border-primary/5" />
      </div>
      <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
        {label}
      </span>
    </div>
  );
}

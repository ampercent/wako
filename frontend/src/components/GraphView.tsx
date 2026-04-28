import React, { useCallback, useRef, useEffect, useMemo, useState } from 'react';
import ForceGraph2D, { ForceGraphMethods } from 'react-force-graph-2d';
import { useStore } from '../store/useStore';
import { Maximize2, ZoomIn, ZoomOut, Crosshair } from 'lucide-react';
import { AttackPathPanel } from './AttackPathPanel';

export const GraphView: React.FC = () => {
  const fgRef = useRef<ForceGraphMethods>();
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
  const containerRef = useRef<HTMLDivElement>(null);
  
  const { 
    graphData, 
    selectedNode, 
    setSelectedNode, 
    setSelectedPID, 
    hoveredNode,
    setHoveredNode,
    highlightedNodes,
    filters,
    searchQuery 
  } = useStore();

  useEffect(() => {
    const handleResize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: containerRef.current.clientHeight
        });
      }
    };
    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const filteredData = useMemo(() => {
    if (!graphData) return { nodes: [], links: [] };
    let nodes = [...graphData.nodes];
    let links = [...graphData.edges].map(link => ({
      ...link,
      source: typeof link.source === 'object' ? (link.source as any).id : link.source,
      target: typeof link.target === 'object' ? (link.target as any).id : link.target
    }));

    if (filters.isSuspiciousOnly) {
      nodes = nodes.filter(n => n.type === 'injection' || n.severity === 'HIGH' || n.severity === 'MEDIUM');
    }
    if (filters.showNetworkOnly) {
      nodes = nodes.filter(n => n.type === 'network' || links.some(l => l.source === n.id && l.type === 'network_connection'));
    }
    if (filters.showInjectionOnly) {
      nodes = nodes.filter(n => n.type === 'injection' || links.some(l => l.source === n.id && l.type === 'injection'));
    }

    if (filters.isSuspiciousOnly || filters.showNetworkOnly || filters.showInjectionOnly) {
      const nodeIds = new Set(nodes.map(n => n.id));
      links = links.filter(l => nodeIds.has(l.source) && nodeIds.has(l.target));
    }

    if (searchQuery) {
       const query = searchQuery.toLowerCase();
       nodes = nodes.filter(n => n.label.toLowerCase().includes(query) || n.id.toLowerCase().includes(query));
       const nodeIds = new Set(nodes.map(n => n.id));
       links = links.filter(l => nodeIds.has(l.source as string) && nodeIds.has(l.target as string));
    }

    return { nodes, links };
  }, [graphData, filters, searchQuery]);

  useEffect(() => {
    if (selectedNode && fgRef.current && filteredData.nodes.length > 0) {
      const node = filteredData.nodes.find(n => n.id === selectedNode);
      if (node && (node as any).x !== undefined) {
         fgRef.current.centerAt((node as any).x, (node as any).y, 1000);
         fgRef.current.zoom(4, 1000);
      }
    }
  }, [selectedNode, filteredData.nodes]);

  const nodeCanvasObject = useCallback((node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const isSelected = selectedNode === node.id;
    const isHovered = hoveredNode === node.id;
    const isHighlighted = highlightedNodes.has(node.id);
    
    // Fading logic: if there is an active selection/highlight AND this node isn't part of it
    const hasActiveHighlight = highlightedNodes.size > 0;
    const shouldFade = hasActiveHighlight && !isHighlighted && !isSelected;

    // Node sizing math based on Threat/Correlation Score
    let baseSize = 6;
    if (node.correlation_score && node.correlation_score > 0) {
       // Cap size scalar to 2.5x max
       const scalar = Math.min((node.correlation_score / 10) * baseSize, baseSize * 2.5);
       baseSize += scalar;
    }
    const size = baseSize;

    let color = '#9CA3AF'; 
    if (node.severity === 'HIGH') color = '#EF4444';
    else if (node.severity === 'MEDIUM') color = '#F97316';
    else if (node.type === 'network') {
       // Flag public IPs visually
       const isPrivate = node.label.startsWith('192.') || node.label.startsWith('10.');
       color = isPrivate ? '#3B82F6' : '#EAB308'; // Public IPs are yellow
    }
    else if (node.type === 'injection') color = '#A855F7'; 
    
    ctx.globalAlpha = shouldFade ? 0.2 : 1;

    // GLOW logic for HIGH threats
    if (node.severity === 'HIGH') {
       ctx.shadowBlur = 15;
       ctx.shadowColor = '#EF4444';
    } else {
       ctx.shadowBlur = 0;
    }

    ctx.beginPath();
    if (node.type === 'network') {
      ctx.rect(node.x - size, node.y - size, size * 2, size * 2);
    } else if (node.type === 'injection') {
      ctx.moveTo(node.x, node.y - size * 1.5);
      ctx.lineTo(node.x + size * 1.5, node.y);
      ctx.lineTo(node.x, node.y + size * 1.5);
      ctx.lineTo(node.x - size * 1.5, node.y);
      ctx.closePath();
    } else {
      ctx.arc(node.x, node.y, size, 0, 2 * Math.PI, false);
    }
    
    ctx.fillStyle = color;
    ctx.fill();

    if (isSelected || isHovered) {
      ctx.lineWidth = 2 / globalScale;
      ctx.strokeStyle = '#FFFFFF';
      ctx.stroke();
      
      ctx.beginPath();
      ctx.arc(node.x, node.y, size * 1.5, 0, 2 * Math.PI, false);
      ctx.fillStyle = `${color}40`;
      ctx.fill();
    }
    
    if (globalScale > 2 || isSelected || isHighlighted) {
      const fontSize = Math.max(10 / globalScale, 4);
      ctx.font = `${fontSize}px Inter, sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = isSelected ? '#FFFFFF' : '#D1D5DB';
      ctx.shadowBlur = 0; // Disable shadow for text
      ctx.fillText(node.label, node.x, node.y + size + fontSize + 2);
    }
    
    ctx.globalAlpha = 1; // Reset
    ctx.shadowBlur = 0;
  }, [selectedNode, hoveredNode, highlightedNodes]);

  return (
    <div className="flex-1 relative bg-[#0B0F19] h-full" ref={containerRef}>
      <AttackPathPanel />
      
      <div className="absolute top-4 right-4 z-10 flex gap-2">
        <button onClick={() => fgRef.current?.zoomToFit(400, 50)} className="bg-gray-800/80 p-2 rounded hover:bg-gray-700 text-gray-300 backdrop-blur" title="Zoom to Fit">
          <Maximize2 className="w-4 h-4" />
        </button>
        <button onClick={() => { fgRef.current?.zoom((fgRef.current?.zoom() || 1) * 1.5, 400); }} className="bg-gray-800/80 p-2 rounded hover:bg-gray-700 text-gray-300 backdrop-blur">
          <ZoomIn className="w-4 h-4" />
        </button>
        <button onClick={() => { fgRef.current?.zoom((fgRef.current?.zoom() || 1) / 1.5, 400); }} className="bg-gray-800/80 p-2 rounded hover:bg-gray-700 text-gray-300 backdrop-blur">
          <ZoomOut className="w-4 h-4" />
        </button>
      </div>

      {dimensions.width > 0 && dimensions.height > 0 && (
        <ForceGraph2D
          ref={fgRef as any}
          width={dimensions.width}
          height={dimensions.height}
          graphData={filteredData}
          nodeLabel={(node: any) => `
               <div style="background: #111827; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 11px; border: 1px solid #374151; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.5);">
                 <strong style="font-size: 13px; color: ${node.severity === 'HIGH' ? '#EF4444' : '#fff'}">${node.label}</strong><br/>
                 <div style="margin-top: 4px; display: flex; flex-direction: column; gap: 2px;">
                    ${node.type === 'network' ? `<span style="color: #EAB308">[External IP Mapping]</span>` : ''}
                    <span style="color: #9CA3AF">Type: <span style="color: #E5E7EB">${node.type}</span></span>
                    ${node.severity ? `<span style="color: #9CA3AF">Severity: <span style="color: ${node.severity === 'HIGH' ? '#EF4444' : '#F97316'}">${node.severity}</span></span>` : ''}
                    <span style="color: #9CA3AF">ID: <span style="color: #E5E7EB">${node.id}</span></span>
                 </div>
               </div>
          `}
          nodeCanvasObject={nodeCanvasObject}
          onNodeHover={(node) => setHoveredNode(node ? node.id as string : null)}
          onNodeClick={(node: any) => {
            setSelectedNode(node.id);
            if (node.type === 'process' && node.id.startsWith('pid_')) {
              setSelectedPID(node.id.replace('pid_', ''));
            } else if (node.type === 'network') {
               const edge = filteredData.links.find((l: any) => l.target.id === node.id);
               if (edge) setSelectedPID(String(edge.source.id).replace('pid_', ''));
            } else if (node.type === 'injection') {
               const edge = filteredData.links.find((l: any) => l.target.id === node.id);
               if (edge) setSelectedPID(String(edge.source.id).replace('pid_', ''));
            }
          }}
          linkColor={() => '#374151'}
          linkWidth={(link: any) => link.type === 'network_connection' || link.type === 'injection' ? 2 : 1}
          linkLineDash={(link: any) => link.type === 'network_connection' ? [4, 4] : undefined}
          linkDirectionalParticles={2}
          linkDirectionalParticleSpeed={0.005}
          linkDirectionalParticleWidth={(link: any) => link.type === 'network_connection' || link.type === 'injection' ? 3 : 0}
          d3VelocityDecay={0.3}
        />
      )}
    </div>
  );
};

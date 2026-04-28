import React, { useEffect, useState, useCallback } from 'react';
import { useHuntStore } from '../../store/useHuntStore';
import { getSavedQueries, deleteSavedQuery, saveHuntQuery } from '../../api/hunting';
import { Bookmark, Trash2, FileInput, Save, Loader2, CheckCircle } from 'lucide-react';

export const SavedQueries: React.FC = React.memo(() => {
  const savedQueries = useHuntStore((s) => s.savedQueries);
  const setSavedQueries = useHuntStore((s) => s.setSavedQueries);
  const setQuery = useHuntStore((s) => s.setQuery);
  const query = useHuntStore((s) => s.query);

  const [saving, setSaving] = useState(false);
  const [saveName, setSaveName] = useState('');
  const [justSaved, setJustSaved] = useState(false);
  const [deletingId, setDeletingId] = useState<number | null>(null);

  const loadQueries = useCallback(() => {
    getSavedQueries()
      .then(setSavedQueries)
      .catch(console.error);
  }, [setSavedQueries]);

  useEffect(() => {
    loadQueries();
  }, [loadQueries]);

  const handleSave = useCallback(async () => {
    if (!saveName.trim() || !query.trim()) return;
    setSaving(true);
    try {
      await saveHuntQuery(saveName, query);
      setSaveName('');
      setJustSaved(true);
      setTimeout(() => setJustSaved(false), 2000);
      loadQueries();
    } catch (err) {
      console.error(err);
    } finally {
      setSaving(false);
    }
  }, [saveName, query, loadQueries]);

  const handleDelete = useCallback(
    async (id: number) => {
      setDeletingId(id);
      try {
        await deleteSavedQuery(id);
        loadQueries();
      } catch {
        // Optimistically remove from local state
        setSavedQueries(savedQueries.filter((q) => q.id !== id));
      } finally {
        setDeletingId(null);
      }
    },
    [loadQueries, setSavedQueries, savedQueries],
  );

  return (
    <div id="hunt-saved-queries" className="space-y-4">
      {/* ── Header ─────────────────────────────────────────────────── */}
      <h3 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.15em] text-gray-500">
        <Bookmark className="h-4 w-4" />
        Saved Queries
        {savedQueries.length > 0 && (
          <span className="ml-auto rounded-full bg-gray-800 px-1.5 py-0.5 text-[9px] font-mono text-gray-500">
            {savedQueries.length}
          </span>
        )}
      </h3>

      {/* ── Save Input ─────────────────────────────────────────────── */}
      <div className="rounded-lg border border-gray-800/80 bg-[#0c0f17] p-3">
        <p className="mb-2 text-[11px] text-gray-500">Save current query:</p>
        <div className="flex gap-2">
          <input
            id="hunt-save-name"
            type="text"
            placeholder="Query name..."
            value={saveName}
            onChange={(e) => setSaveName(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSave()}
            className="flex-1 rounded-md border border-gray-700/80 bg-gray-900/80 px-2.5 py-1.5 text-xs text-white transition-colors focus:border-indigo-500 focus:outline-none"
          />
          <button
            id="hunt-save-btn"
            onClick={handleSave}
            disabled={saving || !saveName.trim() || !query.trim()}
            className={`rounded-md border px-2.5 transition-all disabled:opacity-30 ${
              justSaved
                ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
                : 'border-indigo-500/30 bg-indigo-500/10 text-indigo-300 hover:bg-indigo-500/20'
            }`}
          >
            {saving ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : justSaved ? (
              <CheckCircle className="h-3.5 w-3.5" />
            ) : (
              <Save className="h-3.5 w-3.5" />
            )}
          </button>
        </div>
      </div>

      {/* ── Saved List ─────────────────────────────────────────────── */}
      <div className="max-h-[35vh] space-y-2 overflow-y-auto pr-0.5 scrollbar-thin">
        {savedQueries.map((sq) => (
          <div
            key={sq.id}
            className="group rounded-lg border border-gray-800/60 bg-gray-800/30 p-3 transition-all duration-150 hover:bg-gray-800/60 hover:border-gray-700"
          >
            <div className="mb-1.5 flex items-start justify-between gap-2">
              <h4 className="text-xs font-semibold text-gray-200 leading-tight">{sq.name}</h4>
              <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                <button
                  onClick={() => setQuery(sq.query)}
                  className="rounded p-1 text-gray-400 transition-colors hover:bg-indigo-500/15 hover:text-indigo-300"
                  title="Load query"
                >
                  <FileInput className="h-3.5 w-3.5" />
                </button>
                <button
                  onClick={() => handleDelete(sq.id)}
                  disabled={deletingId === sq.id}
                  className="rounded p-1 text-gray-400 transition-colors hover:bg-red-500/15 hover:text-red-300 disabled:opacity-50"
                  title="Delete query"
                >
                  {deletingId === sq.id ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Trash2 className="h-3.5 w-3.5" />
                  )}
                </button>
              </div>
            </div>
            <p
              className="truncate font-mono text-[11px] text-gray-500 cursor-pointer hover:text-gray-400 transition-colors"
              title={sq.query}
              onClick={() => setQuery(sq.query)}
            >
              {sq.query}
            </p>
            {sq.created_at && (
              <p className="mt-1 text-[9px] text-gray-600">
                {new Date(sq.created_at).toLocaleDateString()}
              </p>
            )}
          </div>
        ))}
      </div>

      {savedQueries.length === 0 && (
        <p className="py-4 text-center text-xs italic text-gray-600">
          No saved queries yet. Run a query and save it above.
        </p>
      )}
    </div>
  );
});

SavedQueries.displayName = 'SavedQueries';

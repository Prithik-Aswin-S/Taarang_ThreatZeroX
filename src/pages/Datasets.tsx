import { useEffect, useState } from "react";
import { Database, ShieldAlert, ShieldCheck, FileText } from "lucide-react";
import { supabase } from "@/lib/supabase";
import { SEED_DATASETS } from "@/data/datasets";
import { Panel, Badge, MetricCard } from "@/components/ui";
import type { Dataset } from "@/types";

export default function DatasetsPage() {
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [selected, setSelected] = useState<Dataset | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const { data } = await supabase.from("datasets").select("*");
      if (data && data.length > 0) {
        setDatasets(data as Dataset[]);
        setSelected(data[0] as Dataset);
      } else {
        const seeded = await supabase.from("datasets").insert(SEED_DATASETS).select("*");
        if (seeded.data) {
          setDatasets(seeded.data as Dataset[]);
          setSelected(seeded.data[0] as Dataset);
        }
      }
      setLoading(false);
    })();
  }, []);

  if (loading) return <div className="text-slate-400 text-sm">Loading dataset library...</div>;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-white tracking-tight">Security Log Dataset Library</h1>
        <p className="text-sm text-slate-400 mt-1">Curated benign + malicious event datasets for detection validation</p>
      </header>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="Total Datasets" value={datasets.length} icon={<Database className="h-4 w-4" />} />
        <MetricCard label="Total Events" value={datasets.reduce((a, d) => a + d.event_count, 0)} icon={<FileText className="h-4 w-4" />} />
        <MetricCard label="Malicious Events" value={datasets.reduce((a, d) => a + d.malicious_count, 0)} tone="threat" icon={<ShieldAlert className="h-4 w-4" />} />
        <MetricCard label="Benign Events" value={datasets.reduce((a, d) => a + d.benign_count, 0)} tone="success" icon={<ShieldCheck className="h-4 w-4" />} />
      </div>

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-4 space-y-3">
          {datasets.map((d) => (
            <button
              key={d.id}
              onClick={() => setSelected(d)}
              className={`w-full text-left glass glass-hover rounded-xl p-4 border transition-all ${
                selected?.id === d.id ? "border-cyan-500/40" : "border-slate-700/40"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold text-slate-200">{d.name}</span>
                <Badge tone="cyber">{d.category}</Badge>
              </div>
              <div className="text-[11px] text-slate-500 mt-1">{d.source_type}</div>
              <div className="flex gap-3 mt-2 text-[11px]">
                <span className="text-red-400">{d.malicious_count} malicious</span>
                <span className="text-emerald-400">{d.benign_count} benign</span>
              </div>
            </button>
          ))}
        </div>

        <div className="col-span-8">
          {selected && (
            <Panel title={selected.name} icon={<Database className="h-4 w-4 text-cyan-400" />} className="h-full">
              <p className="text-sm text-slate-400 mb-4">{selected.description}</p>
              <div className="grid grid-cols-3 gap-3 mb-4">
                <div className="glass rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-slate-200">{selected.event_count}</div>
                  <div className="text-[10px] text-slate-500 uppercase">Total Events</div>
                </div>
                <div className="glass rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-red-400">{selected.malicious_count}</div>
                  <div className="text-[10px] text-slate-500 uppercase">Malicious</div>
                </div>
                <div className="glass rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-emerald-400">{selected.benign_count}</div>
                  <div className="text-[10px] text-slate-500 uppercase">Benign</div>
                </div>
              </div>
              <div className="text-[11px] uppercase text-slate-500 mb-2">Event Samples</div>
              <div className="space-y-1.5 max-h-[420px] overflow-y-auto">
                {selected.events.map((e) => (
                  <div key={e.id} className={`rounded-md px-3 py-2 text-xs font-mono border ${e.is_malicious ? "bg-red-500/5 border-red-500/20" : "bg-slate-700/20 border-slate-700/30"}`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-slate-400">{e.id} · {e.timestamp.slice(11, 19)}</span>
                      <Badge tone={e.is_malicious ? "threat" : "success"}>{e.is_malicious ? "malicious" : "benign"}</Badge>
                    </div>
                    <pre className="whitespace-pre-wrap break-all text-slate-300">{JSON.stringify(e, null, 0).slice(0, 400)}</pre>
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

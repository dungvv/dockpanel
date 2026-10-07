import { useState, useEffect, FormEvent } from "react";
import { api } from "../api";
import { formatDate } from "../utils/format";

// One row of /api/tcp-proxies: a public TCP listen port on this server that
// nginx's stream module forwards to an upstream. kind="database" rows belong
// to a database's remote access and are managed from the Databases page —
// they are listed here for visibility but cannot be deleted here.
interface TcpProxy {
  id: string;
  server_id: string;
  database_id: string | null;
  certificate_id: string | null;
  name: string;
  kind: string;
  listen_port: number;
  upstream_host: string;
  upstream_port: number;
  tls: boolean;
  created_at: string;
}

interface TlsCertificateOption {
  id: string;
  alias: string;
  dns_names: string[];
}

export default function TcpProxies() {
  const [proxies, setProxies] = useState<TcpProxy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  // Create form
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [upstreamHost, setUpstreamHost] = useState("");
  const [upstreamPort, setUpstreamPort] = useState("");
  const [tls, setTls] = useState(false);
  const [certId, setCertId] = useState("");
  const [certs, setCerts] = useState<TlsCertificateOption[]>([]);
  const [submitting, setSubmitting] = useState(false);

  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      const data = await api.get<TcpProxy[]>("/tcp-proxies");
      setProxies(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load TCP proxies");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    api
      .get<TlsCertificateOption[]>("/tls-certificates")
      .then(setCerts)
      .catch(() => setCerts([]));
  }, []);

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccessMsg("");
    setSubmitting(true);
    try {
      await api.post("/tcp-proxies", {
        name: name.trim(),
        upstream_host: upstreamHost.trim(),
        upstream_port: parseInt(upstreamPort, 10),
        tls,
        ...(tls && certId ? { certificate_id: certId } : {}),
      });
      setShowForm(false);
      setName("");
      setUpstreamHost("");
      setUpstreamPort("");
      setTls(false);
      setCertId("");
      setSuccessMsg("TCP proxy created");
      fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create TCP proxy");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (proxy: TcpProxy) => {
    if (confirmDeleteId !== proxy.id) {
      setConfirmDeleteId(proxy.id);
      return;
    }
    setDeletingId(proxy.id);
    setSuccessMsg("");
    try {
      await api.delete(`/tcp-proxies/${proxy.id}`);
      setConfirmDeleteId(null);
      setSuccessMsg(`TCP proxy "${proxy.name}" deleted`);
      fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed");
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="animate-fade-up">
      <div className="page-header">
        <div>
          <h1 className="page-header-title">TCP Proxies</h1>
          <p className="page-header-subtitle">
            Public TCP listeners (ports 40000–44999) forwarded by nginx's stream module
          </p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 transition-colors"
        >
          {showForm ? "Cancel" : "Create Proxy"}
        </button>
      </div>

      <div className="p-6 lg:p-8">
        {error && (
          <div role="alert" className="bg-danger-500/10 text-danger-400 text-sm px-4 py-3 rounded-lg border border-danger-500/20 mb-4">
            {error}
            <button onClick={() => setError("")} className="float-right font-bold" aria-label="Close error">
              &times;
            </button>
          </div>
        )}

        {successMsg && (
          <div className="bg-rust-500/10 text-rust-400 text-sm px-4 py-3 rounded-lg border border-rust-500/20 mb-4">
            {successMsg}
            <button onClick={() => setSuccessMsg("")} className="float-right font-bold" aria-label="Dismiss">
              &times;
            </button>
          </div>
        )}

        {showForm && (
          <form
            onSubmit={handleCreate}
            className="bg-dark-800 rounded-lg border border-dark-500 p-5 mb-6 space-y-4"
          >
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label htmlFor="tp-name" className="block text-sm font-medium text-dark-100 mb-1">
                  Name
                </label>
                <input
                  id="tp-name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                  placeholder="redis-forward"
                  pattern="[a-z0-9]([a-z0-9-]*[a-z0-9])?"
                  title="Lowercase letters, digits and '-'"
                  className="w-full px-3 py-2.5 border border-dark-500 rounded-lg focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none text-sm"
                />
                <p className="text-xs text-dark-300 mt-1">Lowercase letters, digits and '-' — becomes the config filename</p>
              </div>
              <div>
                <label htmlFor="tp-host" className="block text-sm font-medium text-dark-100 mb-1">
                  Upstream host
                </label>
                <input
                  id="tp-host"
                  type="text"
                  value={upstreamHost}
                  onChange={(e) => setUpstreamHost(e.target.value)}
                  required
                  placeholder="127.0.0.1 or [::1]"
                  className="w-full px-3 py-2.5 border border-dark-500 rounded-lg focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none text-sm"
                />
              </div>
              <div>
                <label htmlFor="tp-port" className="block text-sm font-medium text-dark-100 mb-1">
                  Upstream port
                </label>
                <input
                  id="tp-port"
                  type="number"
                  min={1}
                  max={65535}
                  value={upstreamPort}
                  onChange={(e) => setUpstreamPort(e.target.value)}
                  required
                  placeholder="6379"
                  className="w-full px-3 py-2.5 border border-dark-500 rounded-lg focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none text-sm"
                />
              </div>
            </div>
            <div className="flex items-end gap-4 flex-wrap">
              <label className="flex items-center gap-2 text-sm text-dark-200">
                <input
                  type="checkbox"
                  checked={tls}
                  onChange={(e) => setTls(e.target.checked)}
                  className="rounded border-dark-500"
                />
                Terminate TLS on the public listener
              </label>
              {tls && (
                <select
                  value={certId}
                  onChange={(e) => setCertId(e.target.value)}
                  className="px-3 py-2 border border-dark-500 rounded-lg text-sm bg-dark-800"
                  aria-label="TLS certificate"
                >
                  <option value="">-- certificate --</option>
                  {certs.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.alias}
                      {c.dns_names?.length ? ` (${c.dns_names[0]})` : ""}
                    </option>
                  ))}
                </select>
              )}
            </div>
            <div className="flex gap-3">
              <button
                type="submit"
                disabled={submitting || (tls && !certId)}
                className="flex items-center gap-2 px-6 py-2.5 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50 transition-colors"
              >
                {submitting && <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />}
                {submitting ? "Creating..." : "Create Proxy"}
              </button>
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="px-4 py-2 text-sm text-dark-300 border border-dark-600 rounded-lg hover:text-dark-100 hover:border-dark-400 transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        )}

        {loading ? (
          <div className="bg-dark-800 rounded-lg border border-dark-500 animate-pulse">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="px-5 py-4 border-b border-dark-600 last:border-0">
                <div className="h-5 bg-dark-700 rounded w-48" />
              </div>
            ))}
          </div>
        ) : proxies.length === 0 ? (
          <div className="bg-dark-800 rounded-lg border border-dark-500 p-12 text-center">
            <p className="text-dark-200 font-medium">No TCP proxies yet</p>
            <p className="text-dark-300 text-sm mt-2 max-w-md mx-auto">
              Generic forwards are created here; database remote access is managed per
              database on the Databases page.
            </p>
            <button onClick={() => setShowForm(true)} className="mt-3 px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 transition-colors">
              Create your first proxy
            </button>
          </div>
        ) : (
          <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-dark-500 bg-dark-900">
                  <th scope="col" className="text-left text-xs font-medium text-dark-200 uppercase tracking-widest font-mono px-5 py-3">Name</th>
                  <th scope="col" className="text-left text-xs font-medium text-dark-200 uppercase tracking-widest font-mono px-5 py-3">Listen</th>
                  <th scope="col" className="text-left text-xs font-medium text-dark-200 uppercase tracking-widest font-mono px-5 py-3 hidden md:table-cell">Upstream</th>
                  <th scope="col" className="text-left text-xs font-medium text-dark-200 uppercase tracking-widest font-mono px-5 py-3 hidden sm:table-cell">Kind</th>
                  <th scope="col" className="text-left text-xs font-medium text-dark-200 uppercase tracking-widest font-mono px-5 py-3 hidden sm:table-cell">TLS</th>
                  <th scope="col" className="text-left text-xs font-medium text-dark-200 uppercase tracking-widest font-mono px-5 py-3 hidden lg:table-cell">Created</th>
                  <th scope="col" className="text-right text-xs font-medium text-dark-200 uppercase tracking-widest font-mono px-5 py-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-600">
                {proxies.map((p) => (
                  <tr key={p.id} className="hover:bg-dark-700/30 transition-colors">
                    <td className="px-5 py-4 text-sm font-medium text-dark-50 font-mono">{p.name}</td>
                    <td className="px-5 py-4 text-sm text-dark-200 font-mono">:{p.listen_port}</td>
                    <td className="px-5 py-4 text-sm text-dark-200 font-mono hidden md:table-cell">
                      {p.upstream_host}:{p.upstream_port}
                    </td>
                    <td className="px-5 py-4 text-sm text-dark-200 hidden sm:table-cell">{p.kind}</td>
                    <td className="px-5 py-4 text-sm text-dark-200 hidden sm:table-cell">
                      {p.tls ? "TLS" : "\u2014"}
                    </td>
                    <td className="px-5 py-4 text-sm text-dark-200 hidden lg:table-cell">{formatDate(p.created_at)}</td>
                    <td className="px-5 py-4 text-right">
                      {p.database_id ? (
                        <span className="text-xs text-dark-400" title="Managed by the owning database">
                          via Databases
                        </span>
                      ) : confirmDeleteId === p.id ? (
                        <div className="flex items-center justify-end gap-2">
                          <span className="text-xs text-danger-400">Sure?</span>
                          <button
                            onClick={() => handleDelete(p)}
                            disabled={deletingId === p.id}
                            className="px-2 py-1 bg-danger-600 text-white rounded text-xs hover:bg-danger-700 disabled:opacity-50"
                          >
                            {deletingId === p.id ? "..." : "Yes"}
                          </button>
                          <button
                            onClick={() => setConfirmDeleteId(null)}
                            className="px-2 py-1 bg-dark-600 text-dark-100 rounded text-xs hover:bg-dark-500"
                          >
                            No
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => handleDelete(p)}
                          className="text-xs text-danger-500 hover:text-danger-500"
                        >
                          Delete
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

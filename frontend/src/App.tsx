
import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  Bell,
  ChevronDown,
  CircleHelp,
  Clock3,
  Download,
  FileSearch,
  Filter,
  Gauge,
  LayoutDashboard,
  Network,
  Radio,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  X,
  Zap,
} from 'lucide-react'
import './App.css'

type AlertItem = {
  id: string
  time: string
  type: string
  source: string
  destination: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low'
  confidence: number
  status: string
}

type ApiPrediction = {
  ddos_anomaly: boolean
  ddos_anomaly_score: number
  predicted_class_id: number
  predicted_class: string
  class_probabilities: Record<string, number>
  exfil_reconstruction_error: number
  exfil_threshold_configured: boolean
  exfil_status: string
  input_features: Record<string, number>
  note: string
}

type CSVAnalysis = {
  filename: string
  total_records: number
  threats_detected: number
  actual_label_distribution: Record<string, number>
  predicted_class_distribution: Record<string, number>
  isolation_forest_anomaly_count: number
  severity_distribution: Record<string, number>
  high_severity_count: number
  average_detection_confidence: number
  autoencoder_average_reconstruction_error: number
  autoencoder_threshold_configured: boolean
  severity_calculation: string
  preview: {
    actual_label: string
    predicted_class: string
    is_anomaly: boolean
    anomaly_score: number
    exfil_reconstruction_error: number
    severity_score: number
    severity: string
    detection_confidence: number
  }[]
  note: string
}

const initialAlerts: AlertItem[] = [
  {
    id: 'TX-2048',
    time: '10:48:32',
    type: 'DDoS Anomaly',
    source: '192.168.1.105',
    destination: '192.168.1.1',
    severity: 'Critical',
    confidence: 98,
    status: 'New',
  },
  {
    id: 'TX-2047',
    time: '10:46:19',
    type: 'Botnet C2',
    source: '10.0.0.42',
    destination: '172.16.0.12',
    severity: 'High',
    confidence: 94,
    status: 'Investigating',
  },
  {
    id: 'TX-2046',
    time: '10:42:07',
    type: 'Data Exfiltration',
    source: '192.168.1.88',
    destination: '10.10.0.5',
    severity: 'High',
    confidence: 91,
    status: 'New',
  },
  {
    id: 'TX-2045',
    time: '10:39:51',
    type: 'Unusual Traffic',
    source: '10.0.0.18',
    destination: '192.168.1.10',
    severity: 'Medium',
    confidence: 78,
    status: 'Investigating',
  },
  {
    id: 'TX-2044',
    time: '10:35:14',
    type: 'Port Scan Pattern',
    source: '172.16.0.24',
    destination: '192.168.1.20',
    severity: 'Low',
    confidence: 67,
    status: 'Resolved',
  },
]

const navigation = [
  { label: 'Overview', icon: LayoutDashboard },
  { label: 'Live Traffic', icon: Radio },
  { label: 'Threat Detection', icon: ShieldAlert },
  { label: 'Network Flows', icon: Network },
  { label: 'Investigation', icon: FileSearch },
]

function App() {
  const [activeNav, setActiveNav] = useState('Overview')

  const [prediction, setPrediction] = useState<ApiPrediction | null>(null)
  const [apiLoading, setApiLoading] = useState(false)
  const [apiError, setApiError] = useState('')

  const [csvResult, setCsvResult] = useState<CSVAnalysis | null>(null)
  const [csvLoading, setCsvLoading] = useState(false)
  const [csvError, setCsvError] = useState('')

  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('All severities')
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null)
  const [alerts, setAlerts] = useState<AlertItem[]>(initialAlerts)
  const [showFilters, setShowFilters] = useState(false)

  // CSV upload and batch analysis
  const analyzeCSV = async (file: File) => {
    setCsvLoading(true)
    setCsvError('')
    setCsvResult(null)

    try {
      const formData = new FormData()
      formData.append('file', file)

      const response = await fetch(
        'http://127.0.0.1:8000/api/analyze-csv',
        {
          method: 'POST',
          body: formData,
        },
      )

      if (!response.ok) {
        let message = `Upload failed: ${response.status}`

        try {
          const errorData = await response.json()
          const detail = errorData.detail

          message =
            typeof detail === 'string'
              ? detail
              : detail?.message || message
        } catch {
          // Keep the original HTTP error message.
        }

        throw new Error(message)
      }

      const result: CSVAnalysis = await response.json()

      // Basic response validation before displaying dashboard metrics.
      if (
        typeof result.total_records !== 'number' ||
        typeof result.threats_detected !== 'number' ||
        typeof result.high_severity_count !== 'number' ||
        typeof result.average_detection_confidence !== 'number'
      ) {
        throw new Error(
          'The API response is missing one or more dashboard metric fields. Check the backend response.',
        )
      }

      setCsvResult(result)
    } catch (error) {
      setCsvError(
        error instanceof Error
          ? error.message
          : 'Could not analyze CSV.',
      )
    } finally {
      setCsvLoading(false)
    }
  }

  // Single-record model prediction test
  const testPrediction = async () => {
    setApiLoading(true)
    setApiError('')

    try {
      const response = await fetch(
        'http://127.0.0.1:8000/api/predict',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            packet_rate: 120,
            src_ip_entropy: 2.5,
            iat_variance: 0.8,
            outbound_bytes_ratio: 0.6,
            payload_entropy: 4.2,
            dst_port_diversity: 12,
            avg_packet_size: 700,
            burst_density_ratio: 0.4,
          }),
        },
      )

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`)
      }

      const result: ApiPrediction = await response.json()
      setPrediction(result)
    } catch (error) {
      setApiError(
        error instanceof Error
          ? error.message
          : 'Could not connect to the API.',
      )
    } finally {
      setApiLoading(false)
    }
  }

  // Dynamic dashboard metrics from the CSV API response.
  const totalRecords = csvResult?.total_records ?? 0
  const threatsDetected = csvResult?.threats_detected ?? 0
  const highSeverityCount = csvResult?.high_severity_count ?? 0

  const detectionConfidence = csvResult
    ? `${csvResult.average_detection_confidence.toFixed(2)}%`
    : '—'

  const filteredAlerts = useMemo(
    () =>
      alerts.filter((alert) => {
        const matchesSearch = `${alert.id} ${alert.type} ${alert.source} ${alert.destination}`
          .toLowerCase()
          .includes(search.toLowerCase())

        const matchesSeverity =
          severityFilter === 'All severities' ||
          alert.severity === severityFilter

        return matchesSearch && matchesSeverity
      }),
    [alerts, search, severityFilter],
  )

  const markResolved = (id: string) => {
    setAlerts((current) =>
      current.map((alert) =>
        alert.id === id
          ? { ...alert, status: 'Resolved' }
          : alert,
      ),
    )

    setSelectedAlert(null)
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={23} />
          </div>
          <div>
            <strong>
              Trac<span>X</span>
            </strong>
            <small>SECURITY CONSOLE</small>
          </div>
        </div>

        <div className="workspace-label">WORKSPACE</div>

        <div className="workspace">
          <div className="workspace-icon">
            <Network size={17} />
          </div>
          <div>
            <strong>ICS Network</strong>
            <small>Monitoring enclave</small>
          </div>
          <ChevronDown size={15} className="muted-icon" />
        </div>

        <div className="nav-label">MONITOR</div>

        <nav className="navigation">
          {navigation.map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={`nav-item ${activeNav === label ? 'active' : ''}`}
              onClick={() => setActiveNav(label)}
            >
              <Icon size={18} />
              <span>{label}</span>
              {label === 'Threat Detection' && (
                <span className="nav-count">5</span>
              )}
            </button>
          ))}
        </nav>

        <div className="nav-label tools-label">SYSTEM</div>

        <nav className="navigation">
          <button
            className={`nav-item ${activeNav === 'Settings' ? 'active' : ''}`}
            onClick={() => setActiveNav('Settings')}
          >
            <Settings size={18} />
            <span>Settings</span>
          </button>

          <button
            className={`nav-item ${activeNav === 'Help & docs' ? 'active' : ''}`}
            onClick={() => setActiveNav('Help & docs')}
          >
            <CircleHelp size={18} />
            <span>Help &amp; docs</span>
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="sensor-card">
            <div className="sensor-title">
              <span className="live-dot" /> SENSOR STATUS
            </div>
            <strong>Passive monitoring</strong>
            <p>Read-only traffic observation</p>
            <div className="sensor-line">
              <span />
            </div>
            <div className="sensor-footer">
              <span>Sensor 01</span>
              <span className="online">Online</span>
            </div>
          </div>

          <div className="user-profile">
            <div className="avatar">TX</div>
            <div className="user-copy">
              <strong>Security Analyst</strong>
              <small>Local workspace</small>
            </div>
            <Settings size={16} className="muted-icon" />
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumbs">
            <span>Workspace</span>
            <span className="crumb-sep">/</span>
            <strong>{activeNav}</strong>
          </div>

          <div className="topbar-right">
            <div className="environment">
              <span className="live-dot" /> DEMO ENVIRONMENT
            </div>
            <button className="icon-button" aria-label="Notifications">
              <Bell size={18} />
              <i />
            </button>
            <div className="top-avatar">SA</div>
          </div>
        </header>

        <div className="page-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                <span className="eyebrow-line" /> NETWORK INTELLIGENCE
              </div>
              <h1>
                {activeNav === 'Overview'
                  ? 'Security Overview'
                  : activeNav}
              </h1>
              <p className="page-subtitle">
                Monitor network activity and identify potential threats
                across your ICS environment.
              </p>
            </div>

            <div className="heading-actions">
              <button
                className="secondary-button"
                onClick={() => window.location.reload()}
              >
                <Activity size={16} /> Refresh view
              </button>

              <button
                className="primary-button"
                onClick={() =>
                  window.alert(
                    'Report export is not connected yet.',
                  )
                }
              >
                <Download size={16} /> Export report
              </button>
            </div>
          </div>

          {/* CSV Dataset Analysis */}
          <section
            className="panel"
            style={{ padding: 20, marginBottom: 24 }}
          >
            <div className="panel-header">
              <div>
                <h2>CSV Dataset Analysis</h2>
                <p>
                  Upload ICS network traffic data for batch threat analysis
                </p>
              </div>

              <label
                className="primary-button"
                style={{ cursor: 'pointer' }}
              >
                <Download size={16} />
                {csvLoading ? 'Analyzing...' : 'Upload CSV'}

                <input
                  type="file"
                  accept=".csv"
                  disabled={csvLoading}
                  style={{ display: 'none' }}
                  onChange={(event) => {
                    const file = event.target.files?.[0]

                    if (file) {
                      analyzeCSV(file)
                    }

                    event.target.value = ''
                  }}
                />
              </label>
            </div>

            {csvError && (
              <p role="alert" style={{ color: '#fb7185' }}>
                CSV error: {csvError}
              </p>
            )}

            {csvLoading && (
              <p>Processing network traffic records...</p>
            )}

            {csvResult && (
              <div style={{ marginTop: 20 }}>
                <h3>Analysis completed</h3>

                <p>File: {csvResult.filename}</p>

                <p>
                  Total records:{' '}
                  <strong>
                    {csvResult.total_records.toLocaleString()}
                  </strong>
                </p>

                <p>
                  Threats detected:{' '}
                  <strong>
                    {csvResult.threats_detected.toLocaleString()}
                  </strong>
                </p>

                <p>
                  High severity records:{' '}
                  <strong>
                    {csvResult.high_severity_count.toLocaleString()}
                  </strong>
                </p>

                <p>
                  Average detection confidence:{' '}
                  <strong>
                    {csvResult.average_detection_confidence.toFixed(2)}%
                  </strong>
                </p>

                <p>
                  Isolation Forest anomalies:{' '}
                  <strong>
                    {csvResult.isolation_forest_anomaly_count.toLocaleString()}
                  </strong>
                </p>

                <p>
                  Average Autoencoder reconstruction error:{' '}
                  <strong>
                    {csvResult.autoencoder_average_reconstruction_error.toFixed(6)}
                  </strong>
                </p>

                <h4>Severity distribution</h4>

                {Object.entries(csvResult.severity_distribution).map(
                  ([severity, count]) => (
                    <div
                      key={severity}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        padding: '6px 0',
                      }}
                    >
                      <span>{severity}</span>
                      <strong>{count.toLocaleString()}</strong>
                    </div>
                  ),
                )}

                <h4>Actual label distribution</h4>

                {Object.entries(csvResult.actual_label_distribution).map(
                  ([label, count]) => (
                    <div
                      key={label}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        padding: '6px 0',
                      }}
                    >
                      <span>
                        {['Normal', 'DDoS', 'Botnet C2', 'Data Exfiltration'][
                          Number(label)
                        ] || label}
                      </span>
                      <strong>{count.toLocaleString()}</strong>
                    </div>
                  ),
                )}

                <h4>Predicted class distribution</h4>

                {Object.entries(
                  csvResult.predicted_class_distribution,
                ).map(([name, count]) => (
                  <div
                    key={name}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      padding: '6px 0',
                    }}
                  >
                    <span>{name}</span>
                    <strong>{count.toLocaleString()}</strong>
                  </div>
                ))}

                <h4>First 10 prediction results</h4>

                <div style={{ overflowX: 'auto' }}>
                  <table
                    style={{
                      width: '100%',
                      borderCollapse: 'collapse',
                    }}
                  >
                    <thead>
                      <tr>
                        <th>Actual label</th>
                        <th>Predicted class</th>
                        <th>Anomaly</th>
                        <th>Anomaly score</th>
                        <th>Severity</th>
                        <th>Severity score</th>
                        <th>Confidence</th>
                      </tr>
                    </thead>

                    <tbody>
                      {csvResult.preview.map((item, index) => (
                        <tr key={index}>
                          <td>{item.actual_label}</td>
                          <td>{item.predicted_class}</td>
                          <td>{item.is_anomaly ? 'Yes' : 'No'}</td>
                          <td>{item.anomaly_score.toFixed(4)}</td>
                          <td>{item.severity}</td>
                          <td>{item.severity_score.toFixed(2)}</td>
                          <td>
                            {item.detection_confidence.toFixed(2)}%
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <p style={{ fontSize: 12, opacity: 0.7 }}>
                  {csvResult.note}
                </p>
              </div>
            )}
          </section>

          {/* Single-record model prediction */}
          <section
            className="panel"
            style={{ padding: 20, marginBottom: 24 }}
          >
            <div className="panel-header">
              <div>
                <h2>ML Model Prediction Test</h2>
                <p>
                  Send sample network features to the TracX backend
                </p>
              </div>

              <button
                className="primary-button"
                onClick={testPrediction}
                disabled={apiLoading}
              >
                <Activity size={16} />
                {apiLoading ? 'Testing...' : 'Run prediction'}
              </button>
            </div>

            {apiError && (
              <p role="alert" style={{ color: '#fb7185' }}>
                API error: {apiError}
              </p>
            )}

            {prediction && (
              <div style={{ marginTop: 20 }}>
                <h3>
                  XGBoost result: {prediction.predicted_class}
                </h3>

                <p>
                  Isolation Forest anomaly:{' '}
                  <strong>
                    {prediction.ddos_anomaly ? 'Yes' : 'No'}
                  </strong>
                </p>

                <p>
                  Anomaly score:{' '}
                  {prediction.ddos_anomaly_score.toFixed(4)}
                </p>

                <h4>Data Exfiltration Detection — Autoencoder</h4>

                <p>
                  Reconstruction Error:{' '}
                  <strong>
                    {prediction.exfil_reconstruction_error.toFixed(6)}
                  </strong>
                </p>

                <p>
                  Threshold Configured:{' '}
                  <strong>
                    {prediction.exfil_threshold_configured
                      ? 'Yes'
                      : 'No'}
                  </strong>
                </p>

                <p>
                  Autoencoder Status:{' '}
                  <strong>{prediction.exfil_status}</strong>
                </p>

                <h4>Class probabilities</h4>

                {Object.entries(
                  prediction.class_probabilities,
                ).map(([name, probability]) => (
                  <div
                    key={name}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      padding: '6px 0',
                    }}
                  >
                    <span>{name}</span>
                    <strong>
                      {(probability * 100).toFixed(2)}%
                    </strong>
                  </div>
                ))}

                <p style={{ fontSize: 12, opacity: 0.7 }}>
                  {prediction.note}
                </p>
              </div>
            )}
          </section>

          <div className="notice-bar">
            <div className="notice-icon">
              <Shield size={17} />
            </div>
            <div>
              <strong>Passive monitoring enabled</strong>
              <span>
                Traffic is observed in read-only mode. No probes or active
                blocking are performed.
              </span>
            </div>
            <span className="notice-badge">READ ONLY</span>
          </div>

          {/* Four dynamic dashboard metric cards */}
          <section className="metrics-grid">
            <MetricCard
              title="Traffic Observed"
              value={totalRecords.toLocaleString()}
              change={csvResult ? 'Uploaded dataset' : 'No CSV uploaded'}
              positive
              icon={<Activity size={18} />}
              foot="Network flow records"
            />

            <MetricCard
              title="Threats Detected"
              value={threatsDetected.toLocaleString()}
              change={csvResult ? 'Model predictions' : 'No CSV uploaded'}
              positive={false}
              icon={<ShieldAlert size={18} />}
              foot="Non-normal predicted records"
            />

            <MetricCard
              title="High Severity"
              value={highSeverityCount.toLocaleString()}
              change={
                csvResult
                  ? 'Statistical risk assessment'
                  : 'Awaiting CSV'
              }
              positive={false}
              icon={<AlertTriangle size={18} />}
              foot="High + Critical records"
            />

            <MetricCard
              title="Detection Confidence"
              value={detectionConfidence}
              change={
                csvResult
                  ? 'Average model confidence'
                  : 'Awaiting CSV'
              }
              positive
              icon={<Gauge size={18} />}
              foot="Average maximum class probability"
            />
          </section>

          {/* Recent security alerts */}
          <section className="panel alerts-panel">
            <div className="panel-header alerts-heading">
              <div>
                <div className="title-with-dot">
                  <h2>Recent Security Alerts</h2>
                  <span className="alert-count">
                    {filteredAlerts.length}
                  </span>
                </div>
                <p>
                  Investigate and review detected network anomalies
                </p>
              </div>

              <button
                className="secondary-button"
                onClick={() => setShowFilters((visible) => !visible)}
              >
                <Filter size={15} /> Filters <ChevronDown size={14} />
              </button>
            </div>

            {showFilters && (
              <div className="filter-row">
                <label>
                  Severity{' '}
                  <select
                    value={severityFilter}
                    onChange={(event) =>
                      setSeverityFilter(event.target.value)
                    }
                  >
                    <option>All severities</option>
                    <option>Critical</option>
                    <option>High</option>
                    <option>Medium</option>
                    <option>Low</option>
                  </select>
                </label>

                <button
                  className="text-button"
                  onClick={() => {
                    setSeverityFilter('All severities')
                    setSearch('')
                  }}
                >
                  <X size={14} /> Clear filters
                </button>
              </div>
            )}

            <div className="table-toolbar">
              <div className="search-box">
                <Search size={16} />
                <input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search alerts, IP addresses..."
                />
              </div>
              <span className="table-result">
                {filteredAlerts.length} alerts shown
              </span>
            </div>

            <div className="table-scroll">
              <table className="alerts-table">
                <thead>
                  <tr>
                    <th>ALERT ID / TIME</th>
                    <th>THREAT TYPE</th>
                    <th>SOURCE → DESTINATION</th>
                    <th>SEVERITY</th>
                    <th>CONFIDENCE</th>
                    <th>STATUS</th>
                    <th />
                  </tr>
                </thead>

                <tbody>
                  {filteredAlerts.map((alert) => (
                    <tr
                      key={alert.id}
                      onClick={() => setSelectedAlert(alert)}
                    >
                      <td>
                        <strong className="alert-id">
                          {alert.id}
                        </strong>
                        <span className="table-time">
                          <Clock3 size={12} />
                          {alert.time}
                        </span>
                      </td>

                      <td>
                        <span className="threat-type">
                          <span
                            className={`type-dot ${alert.severity.toLowerCase()}`}
                          />
                          {alert.type}
                        </span>
                      </td>

                      <td>
                        <span className="ip-address">
                          {alert.source}
                        </span>
                        <span className="ip-destination">
                          → {alert.destination}
                        </span>
                      </td>

                      <td>
                        <span
                          className={`severity-badge ${alert.severity.toLowerCase()}`}
                        >
                          <i />
                          {alert.severity}
                        </span>
                      </td>

                      <td>
                        <div className="confidence-cell">
                          <div className="confidence-track">
                            <span
                              style={{
                                width: `${alert.confidence}%`,
                              }}
                            />
                          </div>
                          <span>{alert.confidence}%</span>
                        </div>
                      </td>

                      <td>
                        <span
                          className={`status-badge ${alert.status.toLowerCase()}`}
                        >
                          {alert.status}
                        </span>
                      </td>

                      <td>
                        <button
                          className="row-open"
                          aria-label={`View ${alert.id}`}
                          onClick={(event) => {
                            event.stopPropagation()
                            setSelectedAlert(alert)
                          }}
                        >
                          ↗
                        </button>
                      </td>
                    </tr>
                  ))}

                  {filteredAlerts.length === 0 && (
                    <tr>
                      <td colSpan={7} className="empty-state">
                        No alerts match your search.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div className="table-bottom">
              <span>
                Showing <strong>{filteredAlerts.length}</strong> of{' '}
                <strong>{alerts.length}</strong> sample alerts
              </span>

              <button
                className="text-button"
                onClick={() => setActiveNav('Threat Detection')}
              >
                View all alerts <ArrowUpRight size={14} />
              </button>
            </div>
          </section>

          <footer className="page-footer">
            <span>
              TracX Security Console <span className="footer-dot">·</span>{' '}
              Frontend preview
            </span>
            <span>
              <span className="live-dot" /> Passive monitoring concept{' '}
              <span className="footer-dot">·</span> No active response
            </span>
          </footer>
        </div>
      </main>

      {/* Alert investigation drawer */}
      {selectedAlert && (
        <div
          className="drawer-backdrop"
          onClick={() => setSelectedAlert(null)}
        >
          <aside
            className="evidence-drawer"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="drawer-header">
              <div>
                <span className="eyebrow">ALERT INVESTIGATION</span>
                <h2>{selectedAlert.id}</h2>
              </div>

              <button
                className="icon-button"
                onClick={() => setSelectedAlert(null)}
                aria-label="Close details"
              >
                <X size={18} />
              </button>
            </div>

            <span
              className={`severity-badge ${selectedAlert.severity.toLowerCase()}`}
            >
              <i />
              {selectedAlert.severity} severity
            </span>

            <h3>{selectedAlert.type}</h3>

            <p className="drawer-description">
              This sample alert is provided to demonstrate the TracX
              investigation interface. Real evidence will be supplied by
              the connected detection engine.
            </p>

            <div className="evidence-section">
              <h4>EVENT DETAILS</h4>
              <DetailRow label="Alert ID" value={selectedAlert.id} />
              <DetailRow label="Observed at" value={selectedAlert.time} />
              <DetailRow label="Source IP" value={selectedAlert.source} />
              <DetailRow
                label="Destination IP"
                value={selectedAlert.destination}
              />
              <DetailRow
                label="Confidence"
                value={`${selectedAlert.confidence}%`}
              />
              <DetailRow label="Status" value={selectedAlert.status} />
            </div>

            <div className="evidence-note">
              <Zap size={16} />
              <div>
                <strong>Detection evidence</strong>
                <p>
                  Model features, anomaly score and explanation will
                  appear here after backend integration.
                </p>
              </div>
            </div>

            <div className="drawer-actions">
              <button
                className="secondary-button"
                onClick={() => setSelectedAlert(null)}
              >
                Close
              </button>

              <button
                className="primary-button"
                onClick={() => markResolved(selectedAlert.id)}
              >
                <ShieldCheck size={16} /> Mark resolved
              </button>
            </div>
          </aside>
        </div>
      )}
    </div>
  )
}

function MetricCard({
  title,
  value,
  change,
  positive,
  icon,
  foot,
}: {
  title: string
  value: string
  change: string
  positive: boolean
  icon: ReactNode
  foot: string
}) {
  return (
    <div className="metric-card">
      <div className="metric-top">
        <span>{title}</span>
        <span className="metric-icon">{icon}</span>
      </div>

      <div className="metric-value">{value}</div>

      <div className="metric-bottom">
        <span className={`metric-change ${positive ? 'good' : 'bad'}`}>
          {positive ? (
            <ArrowUpRight size={14} />
          ) : (
            <ArrowDownRight size={14} />
          )}
          {change}
        </span>
        <span className="metric-foot">{foot}</span>
      </div>
    </div>
  )
}

function DetailRow({
  label,
  value,
}: {
  label: string
  value: string
}) {
  return (
    <div className="detail-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

export default App


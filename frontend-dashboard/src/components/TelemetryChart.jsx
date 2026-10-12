import {
  ResponsiveContainer,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts'
const tooltip = {
  backgroundColor: '#161B22',
  border: '1px solid #30363D',
  borderRadius: 8,
  color: '#E6EDF3',
}
export default function TelemetryChart({ data, kind = 'risk' }) {
  const baseline = kind === 'baseline'
  const Chart = baseline ? BarChart : LineChart
  return (
    <section
      className="chart-panel"
      aria-label={baseline ? 'Baseline sample counts' : 'Risk score over time'}
    >
      <div className="section-heading">
        <h3>{baseline ? 'Baseline sample counts' : 'Risk score over time'}</h3>
        <span>
          {baseline
            ? 'Latest snapshot · up to 12 containers'
            : 'Latest 30 timestamped incidents'}
        </span>
      </div>
      <div className="chart">
        <ResponsiveContainer width="100%" height="100%">
          <Chart
            data={data}
            margin={{ top: 12, right: 18, left: -20, bottom: 4 }}
          >
            <CartesianGrid stroke="#21262D" vertical={false} />
            <XAxis
              dataKey="label"
              stroke="#8B949E"
              fontSize={11}
              tickLine={false}
              axisLine={false}
              minTickGap={26}
            />
            <YAxis
              stroke="#8B949E"
              fontSize={11}
              tickLine={false}
              axisLine={false}
              domain={baseline ? [0, 'auto'] : [0, 100]}
            />
            <Tooltip
              contentStyle={tooltip}
              labelFormatter={(_, payload) =>
                payload?.[0]?.payload?.fullLabel || ''
              }
            />
            {baseline ? (
              <Bar
                dataKey="value"
                name="Samples"
                fill="#43C6B7"
                radius={[4, 4, 0, 0]}
                isAnimationActive={false}
              />
            ) : (
              <Line
                dataKey="value"
                name="Risk score"
                stroke="#43C6B7"
                strokeWidth={2}
                dot={{ r: 3 }}
                isAnimationActive={false}
              />
            )}
          </Chart>
        </ResponsiveContainer>
      </div>
      <details className="chart-data">
        <summary>View chart data</summary>
        <table>
          <thead>
            <tr>
              <th>{baseline ? 'Container' : 'Time'}</th>
              <th>{baseline ? 'Samples' : 'Risk'}</th>
            </tr>
          </thead>
          <tbody>
            {data.map((row, i) => (
              <tr key={i}>
                <td>{row.fullLabel}</td>
                <td>{row.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </section>
  )
}

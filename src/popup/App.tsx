// src/popup/App.tsx
import * as React from 'react';
import './styles.css';

// Data types
interface MethodScore {
  name: string;
  score: number;
}
interface DetectionResult {
  totalScore: number;
  isSafe: boolean;
  methodScores: MethodScore[];
}

// Component
const DetectionResultComponent: React.FC<{ result: DetectionResult }> = ({ result }) => {
  const { totalScore, isSafe, methodScores } = result;
  return (
    <div className="container">
      <h2 className={`status ${isSafe ? 'safe' : 'danger'}`}>{isSafe ? 'Safe' : 'Phishing Detected'}</h2>
      <p className="total-score">Total Score: {totalScore}</p>
      <ul className="method-list">
        {methodScores.map((m) => (
          <li key={m.name} className="method-item" style={{ gap: '1rem' }}>
            <span className="method-name">{m.name}</span>
            <span className="method-score">{m.score}</span>
          </li>
        ))}
      </ul>
    </div>
  );
};

// Placeholder data
const dummyResult: DetectionResult = {
  totalScore: 75,
  isSafe: true,
  methodScores: [
    { name: 'URL Analysis', score: 20 },
    { name: 'Content Analysis', score: 30 },
    { name: 'Behavior Analysis', score: 25 },
  ],
};

const App: React.FC = () => {
  // TODO: replace with real results via messaging
  const result = dummyResult;
  return <DetectionResultComponent result={result} />;
};

export default App;

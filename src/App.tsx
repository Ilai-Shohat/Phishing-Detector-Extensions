import * as React from 'react';
import { useEffect, useState } from 'react';

type AnalysisResult = {
  isPhishing: boolean;
  score: number;
  indicators: string[];
};

const App: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    chrome.tabs.query(
      { active: true, currentWindow: true },
      (tabs) => {
        const tabId = tabs[0]?.id;
        if (!tabId) {
          setError('Could not find active tab');
          setLoading(false);
          return;
        }

        chrome.tabs.sendMessage(
          tabId,
          { action: 'analyzePhishing' },
          (response) => {
            if (chrome.runtime.lastError) {
              setError(chrome.runtime.lastError.message || 'Unknown error');
            } else if (response?.result) {
              setResult(response.result);
            } else {
              setError('No response from content script');
            }
            setLoading(false);
          }
        );
      }
    );
  }, []);

  if (loading) return <div className="popup">Loading…</div>;
  if (error) return <div className="popup error">Error: {error}</div>;

  return (
    <div className="popup">
      <h1>Phishing Check</h1>
      <p>Result: <strong>{result?.isPhishing ? 'Likely Phishing' : 'Safe'}</strong></p>
      <p>Score: {result?.score}</p>
      <ul>
        {result?.indicators.map((ind, i) => <li key={i}>{ind}</li>)}
      </ul>
    </div>
  );
};

export default App;
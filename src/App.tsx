import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Layout } from './components/Layout';
import { LiveScanner } from './pages/Scanner';
import EmailPhishing from './pages/EmailPhishing';
import { Dashboard } from './pages/Dashboard';
import { Alerts } from './pages/Alerts';
import { AttackGraph } from './pages/AttackGraph';
import SentinelVoice from './pages/SentinelVoice';
import SentinelWaveModule from './pages/NetworkScanner';
import { ApiAccess } from './pages/ApiAccess';
import { Copilot } from './pages/Copilot';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  useEffect(() => {
    // Sync with location hash
    const handleHashChange = () => {
      const hash = window.location.hash.replace(/^#\/?/, '').trim();
      if (hash === 'attack-graph' || hash === 'graph') {
        setActiveTab('graph');
      } else if (hash === 'scanner') {
        setActiveTab('scanner');
      } else if (hash === 'phishing') {
        setActiveTab('phishing');
      } else if (hash === 'alerts') {
        setActiveTab('alerts');
      } else if (hash === 'dashboard') {
        setActiveTab('dashboard');
      } else if (hash === 'copilot') {
        setActiveTab('copilot');
      } else if (hash === 'voice') {
        setActiveTab('voice');
      } else if (hash === 'wave') {
        setActiveTab('wave');
      } else if (hash === 'api') {
        setActiveTab('api');
      }
    };

    const handleCustomNavigate = (e: Event) => {
      const customEvent = e as CustomEvent<string>;
      if (customEvent.detail) {
        setActiveTab(customEvent.detail);
      }
    };

    window.addEventListener('hashchange', handleHashChange);
    window.addEventListener('neuroshield:navigate', handleCustomNavigate);

    // Initial check
    if (window.location.hash) {
      handleHashChange();
    }

    return () => {
      window.removeEventListener('hashchange', handleHashChange);
      window.removeEventListener('neuroshield:navigate', handleCustomNavigate);
    };
  }, []);

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard />;
      case 'scanner':
        return <LiveScanner />;
      case 'phishing':
        return <EmailPhishing />;
      case 'copilot':
        return <Copilot />;
      case 'voice':
        return <SentinelVoice />;
      case 'wave':
        return <SentinelWaveModule />;
      case 'alerts':
        return <Alerts />;
      case 'graph':
        return <AttackGraph />;
      case 'api':
        return <ApiAccess />;
      default:
        return (
          <div className="flex items-center justify-center h-full">
            <div className="text-center space-y-4">
              <div className="text-cyber-blue/50 text-6xl font-mono mb-4">404</div>
              <h2 className="text-xl font-mono text-cyber-muted">MODULE_NOT_FOUND</h2>
              <p className="text-sm text-cyber-muted/50">The requested interface is under construction.</p>
            </div>
          </div>
        );
    }
  };

  return (
    <Layout activeTab={activeTab} setActiveTab={setActiveTab}>
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 15, filter: 'blur(8px)' }}
          animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
          exit={{ opacity: 0, y: -15, filter: 'blur(8px)' }}
          transition={{ duration: 0.3, ease: 'easeInOut' }}
          className="h-full w-full flex flex-col"
        >
          {renderContent()}
        </motion.div>
      </AnimatePresence>
    </Layout>
  );
}

export default App;

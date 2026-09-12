import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Layout } from './components/Layout';
import { LandingPage } from './pages/LandingPage';
import { Dashboard } from './pages/Dashboard';
import EmailPhishing from './pages/EmailPhishing';
import { LiveScanner } from './pages/Scanner';
import { Alerts } from './pages/Alerts';
import SentinelVoice from './pages/SentinelVoice';
import { ApiAccess } from './pages/ApiAccess';
import { Copilot } from './pages/Copilot';
import { Settings } from './pages/Settings';
import { FeedbackDashboard } from './pages/FeedbackDashboard';
import { GuardPage } from './pages/Guard';

function App() {
  const [activeTab, setActiveTab] = useState<string>(() => {
    if (typeof window !== 'undefined' && window.location.hash) {
      const hash = window.location.hash.replace(/^#\/?/, '').trim().toLowerCase();
      if (hash === 'landing' || hash === 'home') return 'landing';
      if (hash === 'dashboard' || hash === 'overview') return 'dashboard';
      if (hash === 'phishing' || hash === 'email' || hash === 'inbox') return 'phishing';
      if (hash === 'guard') return 'guard';
      if (hash === 'scanner' || hash === 'network') return 'scanner';
      if (hash === 'alerts') return 'alerts';
      if (hash === 'copilot') return 'copilot';
      if (hash === 'voice') return 'voice';
      if (hash === 'feedback') return 'feedback';
      if (hash === 'api') return 'api';
      if (hash === 'settings') return 'settings';
    }
    return 'landing';
  });

  useEffect(() => {
    // Sync with location hash
    const handleHashChange = () => {
      const hash = window.location.hash.replace(/^#\/?/, '').trim().toLowerCase();
      if (hash === 'landing' || hash === 'home') {
        setActiveTab('landing');
      } else if (hash === 'dashboard' || hash === 'overview' || hash === 'attack-graph' || hash === 'graph' || hash === 'wave') {
        setActiveTab('dashboard');
      } else if (hash === 'phishing' || hash === 'email' || hash === 'inbox' || hash === 'analyze') {
        setActiveTab('phishing');
      } else if (hash === 'guard') {
        setActiveTab('guard');
      } else if (hash === 'scanner' || hash === 'network' || hash === 'tunnel') {
        setActiveTab('scanner');
      } else if (hash === 'alerts' || hash === 'incidents') {
        setActiveTab('alerts');
      } else if (hash === 'copilot' || hash === 'soc') {
        setActiveTab('copilot');
      } else if (hash === 'voice' || hash === 'deepfake') {
        setActiveTab('voice');
      } else if (hash === 'feedback' || hash === 'hitl' || hash === 'learning') {
        setActiveTab('feedback');
      } else if (hash === 'api' || hash === 'tokens' || hash === 'developer') {
        setActiveTab('api');
      } else if (hash === 'settings' || hash === 'config') {
        setActiveTab('settings');
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

    return () => {
      window.removeEventListener('hashchange', handleHashChange);
      window.removeEventListener('neuroshield:navigate', handleCustomNavigate);
    };
  }, []);

  const handleTabChange = (newTab: string) => {
    setActiveTab(newTab);
    window.location.hash = newTab;
  };

  const renderContent = () => {
    switch (activeTab) {
      case 'landing':
        return (
          <LandingPage 
            onNavigateToDashboard={() => handleTabChange('dashboard')} 
            onNavigateToInboxShield={() => handleTabChange('phishing')} 
            onNavigateToScanner={() => handleTabChange('scanner')} 
          />
        );
      case 'dashboard':
        return <Dashboard />;
      case 'phishing':
      case 'analyze':
        return <EmailPhishing />;
      case 'guard':
        return (
          <GuardPage
            onNavigateToForensics={() => handleTabChange('copilot')}
            onNavigateTab={(tab) => handleTabChange(tab)}
          />
        );
      case 'scanner':
        return <LiveScanner />;
      case 'copilot':
        return <Copilot />;
      case 'voice':
        return <SentinelVoice />;
      case 'alerts':
        return <Alerts />;
      case 'feedback':
        return <FeedbackDashboard />;
      case 'api':
        return <ApiAccess />;
      case 'settings':
        return <Settings />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <Layout activeTab={activeTab} setActiveTab={handleTabChange}>
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 12, filter: 'blur(6px)' }}
          animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
          exit={{ opacity: 0, y: -12, filter: 'blur(6px)' }}
          transition={{ duration: 0.25, ease: 'easeOut' }}
          className="h-full w-full flex flex-col"
        >
          {renderContent()}
        </motion.div>
      </AnimatePresence>
    </Layout>
  );
}

export default App;

import { useEffect, useRef, useImperativeHandle, forwardRef } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';

interface TerminalViewProps {
  logs: string;
}

export const TerminalView = forwardRef((props: TerminalViewProps, ref) => {
  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const lastLogsRef = useRef<string>("");

  useEffect(() => {
    if (terminalRef.current && !xtermRef.current) {
      const term = new Terminal({
        convertEol: true,
        rows: 20,
        theme: {
          background: '#1a1a1a',
          foreground: '#e0e0e0',
        },
      });
      const fitAddon = new FitAddon();
      
      xtermRef.current = term;
      fitAddonRef.current = fitAddon;

      term.loadAddon(fitAddon);
      term.open(terminalRef.current);
      fitAddon.fit();
    }

    return () => {
      // xtermRef.current?.dispose();
    };
  }, []);

  useEffect(() => {
    if (xtermRef.current) {
      const newLogs = props.logs.substring(lastLogsRef.current.length);
      if (newLogs) {
        xtermRef.current.write(newLogs);
      }
      lastLogsRef.current = props.logs;
    }
  }, [props.logs]);

  useImperativeHandle(ref, () => ({
    clear: () => {
      xtermRef.current?.clear();
      lastLogsRef.current = "";
    },
  }));

  return <div ref={terminalRef} style={{ height: '100%', width: '100%' }} />;
});

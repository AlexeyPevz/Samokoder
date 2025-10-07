import { useState, useEffect, useRef } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { 
  AlertCircle, 
  CheckCircle, 
  Loader2, 
  Wrench, 
  Play, 
  Square,
  BarChart3,
  Monitor,
  Smartphone,
  Trash2
} from "lucide-react"
import { Project } from "@/api/projects"
import { startPreview, stopPreview } from "@/api/preview"
import { getTokenUsageSummary, type TokenUsageSummary } from "@/api/usage"
import { TerminalView } from "./TerminalView";

interface ProjectPreviewProps {
  project: Project;
  onSendCommand: (command: string, payload?: any) => void;
  buildLogs: string;
  buildStatus: "success" | "error" | "building" | "unknown";
  isFixing: boolean;
  onClearLogs: () => void;
}

export default function ProjectPreview({ project, onSendCommand, buildLogs, buildStatus, isFixing, onClearLogs }: ProjectPreviewProps) {
  const terminalRef = useRef<{ clear: () => void }>(null);
  const [viewMode, setViewMode] = useState<'desktop' | 'mobile'>('desktop');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showFixButton, setShowFixButton] = useState(false); // This can remain local
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [isPreviewRunning, setIsPreviewRunning] = useState(false);
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);
  const [tokenUsage, setTokenUsage] = useState<TokenUsageSummary | null>(null);

  useEffect(() => {
    loadTokenUsage();
    const interval = setInterval(loadTokenUsage, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    // Show fix button if build status is error
    setShowFixButton(buildStatus === 'error');
  }, [buildStatus]);

  const loadTokenUsage = async () => {
    try {
      const summary = await getTokenUsageSummary();
      setTokenUsage(summary);
    } catch (error) {
      // Error loading token usage
    }
  };

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => setIsRefreshing(false), 1000);
  };

  const handleFixErrors = async () => {
    onSendCommand('fix-errors', { log: buildLogs });
  };

  const handleClearLogs = () => {
    terminalRef.current?.clear();
    onClearLogs();
  };

  const handleStartPreview = async () => {
    setIsLoadingPreview(true);
    try {
      const previewInfo = await startPreview(project.id);
      setPreviewUrl(previewInfo.url);
      setIsPreviewRunning(true);
      project.previewUrl = previewInfo.url;
    } catch (error) {
      // Error starting preview
    } finally {
      setIsLoadingPreview(false);
    }
  };

  const handleStopPreview = async () => {
    setIsLoadingPreview(true);
    try {
      await stopPreview(project.id);
      setPreviewUrl(null);
      setIsPreviewRunning(false);
      project.previewUrl = undefined;
    } catch (error) {
      // Error stopping preview
    } finally {
      setIsLoadingPreview(false);
    }
  };

  const getTotalTokens = () => tokenUsage?.totals.tokens ?? 0;
  const getTotalRequests = () => tokenUsage?.totals.requests ?? 0;
  const getUsageByProvider = () => tokenUsage?.providers ?? {};

  return (
    <div className="flex flex-col h-full bg-white/50 backdrop-blur-sm">
      <div className="p-4 border-b bg-white/80 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={handleStartPreview} disabled={isLoadingPreview || isPreviewRunning}>
            <Play className="h-4 w-4 mr-2" />
            Start Preview
          </Button>
          <Button variant="outline" size="sm" onClick={handleStopPreview} disabled={isLoadingPreview || !isPreviewRunning}>
            <Square className="h-4 w-4 mr-2" />
            Stop Preview
          </Button>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setViewMode('desktop')} disabled={viewMode === 'desktop'}>
            <Monitor className="h-4 w-4" />
          </Button>
          <Button variant="outline" size="sm" onClick={() => setViewMode('mobile')} disabled={viewMode === 'mobile'}>
            <Smartphone className="h-4 w-4" />
          </Button>
        </div>
      </div>

      <div className="flex-1 p-4 overflow-auto">
        <div className="h-full flex flex-col">
          {showFixButton && (
            <div className="mb-4">
              <Button onClick={handleFixErrors} disabled={isFixing} className="w-full">
                {isFixing ? (
                  <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Исправляем...</>
                ) : (
                  <><Wrench className="mr-2 h-4 w-4" />Исправить ошибки</>
                )}
              </Button>
            </div>
          )}
          
          {buildLogs && (
            <Card className="mb-4 flex-shrink-0">
              <CardHeader className="flex flex-row items-center justify-between py-2">
                <CardTitle className="text-sm font-medium">Логи выполнения</CardTitle>
                <Button variant="ghost" size="sm" onClick={handleClearLogs}><Trash2 className="h-4 w-4 mr-1"/>Очистить</Button>
              </CardHeader>
              <CardContent>
                <div className="h-64 bg-gray-900 rounded-md">
                  <TerminalView ref={terminalRef} logs={buildLogs} />
                </div>
              </CardContent>
            </Card>
          )}

          <div className="flex-1 flex items-center justify-center">
            {isPreviewRunning && previewUrl ? (
              <iframe
                src={previewUrl}
                className={`w-full h-full border rounded-md ${viewMode === 'mobile' ? 'max-w-sm' : ''}`}
                title="Project Preview"
              />
            ) : (
              <div className="text-center">
                <p className="text-muted-foreground">Preview is not running.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
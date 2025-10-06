import React, { useState, useEffect } from 'react';
import { usePerformance } from '../hooks/usePerformance';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { RefreshCw, CheckCircle, XCircle, AlertCircle } from 'lucide-react';

interface PerformanceMonitorProps {
  showDetails?: boolean;
  className?: string;
}

export const PerformanceMonitor: React.FC<PerformanceMonitorProps> = ({ 
  showDetails = false, 
  className = '' 
}) => {
  const { getVitals, getVitalsReport } = usePerformance();
  const [vitals, setVitals] = useState<any>(null);
  const [isVisible, setIsVisible] = useState(showDetails);

  const refreshVitals = () => {
    const currentVitals = getVitals();
    setVitals(currentVitals);
  };

  useEffect(() => {
    // Initial load
    refreshVitals();
    
    // Refresh every 5 seconds
    const interval = setInterval(refreshVitals, 5000);
    
    return () => clearInterval(interval);
  }, []);

  const getVitalStatus = (value: number | null, threshold: number, isLowerBetter = true) => {
    if (value === null) return 'unknown';
    if (isLowerBetter) {
      return value <= threshold ? 'good' : 'poor';
    } else {
      return value >= threshold ? 'good' : 'poor';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'good':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'poor':
        return <XCircle className="h-4 w-4 text-red-500" />;
      default:
        return <AlertCircle className="h-4 w-4 text-yellow-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'good':
        return 'bg-green-100 text-green-800';
      case 'poor':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-yellow-100 text-yellow-800';
    }
  };

  if (!vitals) {
    return (
      <div className={`p-4 ${className}`}>
        <div className="flex items-center space-x-2">
          <RefreshCw className="h-4 w-4 animate-spin" />
          <span className="text-sm text-muted-foreground">Loading performance data...</span>
        </div>
      </div>
    );
  }

  const lcpStatus = getVitalStatus(vitals.lcp, 2500);
  const inpStatus = getVitalStatus(vitals.inp, 200);
  const clsStatus = getVitalStatus(vitals.cls, 0.1);

  return (
    <div className={`space-y-4 ${className}`}>
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">Core Web Vitals</h3>
        <Button
          variant="outline"
          size="sm"
          onClick={refreshVitals}
          className="flex items-center space-x-2"
        >
          <RefreshCw className="h-4 w-4" />
          <span>Refresh</span>
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* LCP */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center space-x-2">
              {getStatusIcon(lcpStatus)}
              <span>LCP</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <div className="text-2xl font-bold">
                {vitals.lcp ? `${(vitals.lcp / 1000).toFixed(2)}s` : 'N/A'}
              </div>
              <Badge className={getStatusColor(lcpStatus)}>
                {lcpStatus === 'good' ? 'Good' : lcpStatus === 'poor' ? 'Poor' : 'Unknown'}
              </Badge>
              <p className="text-xs text-muted-foreground">
                Target: ≤ 2.5s
              </p>
            </div>
          </CardContent>
        </Card>

        {/* INP */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center space-x-2">
              {getStatusIcon(inpStatus)}
              <span>INP</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <div className="text-2xl font-bold">
                {vitals.inp ? `${vitals.inp.toFixed(0)}ms` : 'N/A'}
              </div>
              <Badge className={getStatusColor(inpStatus)}>
                {inpStatus === 'good' ? 'Good' : inpStatus === 'poor' ? 'Poor' : 'Unknown'}
              </Badge>
              <p className="text-xs text-muted-foreground">
                Target: ≤ 200ms
              </p>
            </div>
          </CardContent>
        </Card>

        {/* CLS */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center space-x-2">
              {getStatusIcon(clsStatus)}
              <span>CLS</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <div className="text-2xl font-bold">
                {vitals.cls ? vitals.cls.toFixed(3) : 'N/A'}
              </div>
              <Badge className={getStatusColor(clsStatus)}>
                {clsStatus === 'good' ? 'Good' : clsStatus === 'poor' ? 'Poor' : 'Unknown'}
              </Badge>
              <p className="text-xs text-muted-foreground">
                Target: ≤ 0.1
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {isVisible && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Additional Metrics</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <div className="font-medium">FCP</div>
                <div className="text-muted-foreground">
                  {vitals.fcp ? `${(vitals.fcp / 1000).toFixed(2)}s` : 'N/A'}
                </div>
              </div>
              <div>
                <div className="font-medium">FID</div>
                <div className="text-muted-foreground">
                  {vitals.fid ? `${vitals.fid.toFixed(0)}ms` : 'N/A'}
                </div>
              </div>
              <div>
                <div className="font-medium">TTFB</div>
                <div className="text-muted-foreground">
                  {vitals.ttfb ? `${vitals.ttfb.toFixed(0)}ms` : 'N/A'}
                </div>
              </div>
              <div>
                <div className="font-medium">Status</div>
                <div className="text-muted-foreground">
                  {lcpStatus === 'good' && inpStatus === 'good' && clsStatus === 'good' 
                    ? 'All Good' 
                    : 'Needs Attention'
                  }
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Button
        variant="ghost"
        size="sm"
        onClick={() => setIsVisible(!isVisible)}
        className="w-full"
      >
        {isVisible ? 'Hide Details' : 'Show Details'}
      </Button>
    </div>
  );
};

export default PerformanceMonitor;
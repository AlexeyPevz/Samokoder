import { APIKeyManager } from "@/components/settings/APIKeyManager";
import { GitHubSettings } from "@/components/settings/GitHubSettings";
import { GitVerseSettings } from "@/components/settings/GitVerseSettings";

export default function SettingsPage() {
  return (
    <div className="container mx-auto py-8">
      <h1 className="text-3xl font-bold mb-6">Настройки</h1>
      <div className="space-y-8">
        <APIKeyManager />
        <GitHubSettings />
        <GitVerseSettings />
        {/* Other settings components can be added here in the future */}
      </div>
    </div>
  );
}

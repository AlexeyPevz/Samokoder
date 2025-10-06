import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function GitHubSettings() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Интеграция с GitHub</CardTitle>
        <CardDescription>
          Подключите свой аккаунт GitHub для сохранения проектов и автоматической отправки изменений.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <a href="/api/v1/auth/github" rel="noopener noreferrer">
          <Button>Подключить GitHub</Button>
        </a>
      </CardContent>
    </Card>
  );
}

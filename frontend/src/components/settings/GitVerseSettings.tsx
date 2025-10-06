import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/useToast";
import { setGitVerseToken } from "@/api/gitverse"; // This file needs to be created

export function GitVerseSettings() {
  const { toast } = useToast();
  const [token, setToken] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleSave = async () => {
    if (!token) {
      toast({
        title: "Ошибка",
        description: "Пожалуйста, введите токен.",
        variant: "destructive",
      });
      return;
    }
    setIsLoading(true);
    try {
      await setGitVerseToken(token); // This function needs to be created
      toast({
        title: "Успех",
        description: "Токен Гитверс успешно сохранен.",
      });
      setToken("");
    } catch (error) {
      toast({
        title: "Ошибка сохранения",
        description: (error as Error).message,
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Интеграция с Гитверс</CardTitle>
        <CardDescription>
          Подключите свой аккаунт Гитверс для сохранения проектов. Токен можно получить в настройках вашего профиля Гитверс.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Input
          type="password"
          placeholder="Ваш токен Гитверс..."
          value={token}
          onChange={(e) => setToken(e.target.value)}
          disabled={isLoading}
        />
        <Button onClick={handleSave} disabled={isLoading}>
          {isLoading ? "Сохранение..." : "Сохранить токен"}
        </Button>
      </CardContent>
    </Card>
  );
}

-- Исправленная настройка Supabase для проекта Самокодер
-- Выполните этот SQL в Supabase Dashboard → SQL Editor

-- 1. Создание таблиц
CREATE TABLE IF NOT EXISTS profiles (
    id UUID REFERENCES auth.users(id) PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT,
    avatar_url TEXT,
    subscription_tier TEXT DEFAULT 'free' CHECK (subscription_tier IN ('free', 'starter', 'professional', 'business', 'enterprise')),
    subscription_status TEXT DEFAULT 'active' CHECK (subscription_status IN ('active', 'canceled', 'past_due', 'trialing')),
    subscription_ends_at TIMESTAMP WITH TIME ZONE,
    api_credits_balance DECIMAL(10,2) DEFAULT 0.00,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
    default_model TEXT DEFAULT 'deepseek/deepseek-v3',
    default_provider TEXT DEFAULT 'openrouter',
    auto_export BOOLEAN DEFAULT false,
    notifications_email BOOLEAN DEFAULT true,
    notifications_generation BOOLEAN DEFAULT true,
    theme TEXT DEFAULT 'light' CHECK (theme IN ('light', 'dark', 'auto')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id)
);

CREATE TABLE IF NOT EXISTS ai_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    website_url TEXT,
    documentation_url TEXT,
    requires_api_key BOOLEAN DEFAULT true,
    is_active BOOLEAN DEFAULT true,
    pricing_info JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ai_models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID REFERENCES ai_providers(id) ON DELETE CASCADE,
    model_name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT,
    context_window INTEGER,
    is_free BOOLEAN DEFAULT false,
    cost_per_token DECIMAL(10,8),
    max_tokens INTEGER,
    capabilities TEXT[] DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(provider_id, model_name)
);

CREATE TABLE IF NOT EXISTS user_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
    provider_id UUID REFERENCES ai_providers(id) ON DELETE CASCADE,
    key_name TEXT NOT NULL,
    api_key_encrypted TEXT NOT NULL,
    api_key_last_4 TEXT NOT NULL,
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, provider_id, key_name)
);

CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'draft' CHECK (status IN ('draft', 'generating', 'completed', 'error', 'archived')),
    ai_config JSONB DEFAULT '{}',
    tech_stack JSONB DEFAULT '{}',
    file_count INTEGER DEFAULT 0,
    total_size_bytes BIGINT DEFAULT 0,
    generation_time_seconds INTEGER DEFAULT 0,
    generation_progress INTEGER DEFAULT 0 CHECK (generation_progress >= 0 AND generation_progress <= 100),
    current_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    archived_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS api_usage_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    provider_name TEXT NOT NULL,
    model_name TEXT NOT NULL,
    tokens_input INTEGER NOT NULL DEFAULT 0,
    tokens_output INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd DECIMAL(10,6) NOT NULL DEFAULT 0.000000,
    billed_to TEXT NOT NULL CHECK (billed_to IN ('user_key', 'platform_credits', 'free_tier')),
    operation_type TEXT CHECK (operation_type IN ('chat', 'generation', 'analysis', 'testing')),
    agent_type TEXT CHECK (agent_type IN ('ProductOwner', 'Architect', 'Developer', 'Tester')),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS subscription_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_tier TEXT UNIQUE NOT NULL,
    max_projects INTEGER NOT NULL DEFAULT 0,
    max_active_projects INTEGER NOT NULL DEFAULT 0,
    max_generations_per_month INTEGER NOT NULL DEFAULT 0,
    max_ai_credits_per_month DECIMAL(10,2) DEFAULT 0.00,
    max_file_size_mb INTEGER NOT NULL DEFAULT 0,
    can_use_custom_models BOOLEAN DEFAULT false,
    can_export_projects BOOLEAN DEFAULT true,
    can_use_advanced_agents BOOLEAN DEFAULT false,
    priority_support BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Включение RLS
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_usage_log ENABLE ROW LEVEL SECURITY;

-- 3. RLS политики
CREATE POLICY "Users see own profile" ON profiles FOR ALL USING (auth.uid() = id);
CREATE POLICY "Users see own settings" ON user_settings FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Users see own API keys" ON user_api_keys FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Users see own projects" ON projects FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Users see own usage" ON api_usage_log FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Anyone can view providers" ON ai_providers FOR SELECT USING (is_active = true);
CREATE POLICY "Anyone can view models" ON ai_models FOR SELECT USING (is_active = true);
CREATE POLICY "Anyone can view limits" ON subscription_limits FOR SELECT USING (true);

-- 4. Триггеры для updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_profiles_updated_at BEFORE UPDATE ON profiles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_user_settings_updated_at BEFORE UPDATE ON user_settings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_projects_updated_at BEFORE UPDATE ON projects FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 5. Начальные данные
INSERT INTO ai_providers (name, display_name, website_url, documentation_url, requires_api_key, is_active) VALUES
('openrouter', 'OpenRouter', 'https://openrouter.ai', 'https://openrouter.ai/docs', true, true),
('openai', 'OpenAI', 'https://openai.com', 'https://platform.openai.com/docs', true, true),
('anthropic', 'Anthropic', 'https://anthropic.com', 'https://docs.anthropic.com', true, true),
('groq', 'Groq', 'https://groq.com', 'https://console.groq.com/docs', true, true)
ON CONFLICT (name) DO NOTHING;

INSERT INTO ai_models (provider_id, model_name, display_name, description, context_window, is_free, cost_per_token, max_tokens, capabilities) VALUES
((SELECT id FROM ai_providers WHERE name = 'openrouter'), 'deepseek/deepseek-v3', 'DeepSeek V3', 'Мощная модель для кодирования', 128000, true, 0.000000, 4096, ARRAY['code', 'chat']),
((SELECT id FROM ai_providers WHERE name = 'openrouter'), 'qwen/qwen-2.5-coder-32b', 'Qwen 2.5 Coder 32B', 'Специализированная модель для программирования', 128000, true, 0.000000, 4096, ARRAY['code']),
((SELECT id FROM ai_providers WHERE name = 'openai'), 'gpt-4o-mini', 'GPT-4o Mini', 'Быстрая и доступная модель OpenAI', 128000, false, 0.000150, 16384, ARRAY['chat', 'code']),
((SELECT id FROM ai_providers WHERE name = 'openai'), 'gpt-4o', 'GPT-4o', 'Самая мощная модель OpenAI', 128000, false, 0.005000, 4096, ARRAY['chat', 'code', 'analysis']),
((SELECT id FROM ai_providers WHERE name = 'anthropic'), 'claude-3-haiku-20240307', 'Claude 3 Haiku', 'Быстрая модель Anthropic', 200000, false, 0.000250, 4096, ARRAY['chat', 'code']),
((SELECT id FROM ai_providers WHERE name = 'anthropic'), 'claude-3-sonnet-20240229', 'Claude 3 Sonnet', 'Сбалансированная модель Anthropic', 200000, false, 0.003000, 4096, ARRAY['chat', 'code', 'analysis']),
((SELECT id FROM ai_providers WHERE name = 'groq'), 'llama-3-8b-8192', 'Llama 3 8B', 'Быстрая модель на Groq', 8192, true, 0.000000, 4096, ARRAY['chat', 'code']),
((SELECT id FROM ai_providers WHERE name = 'groq'), 'llama-3-70b-8192', 'Llama 3 70B', 'Мощная модель на Groq', 8192, true, 0.000000, 4096, ARRAY['chat', 'code'])
ON CONFLICT (provider_id, model_name) DO NOTHING;

INSERT INTO subscription_limits (subscription_tier, max_projects, max_active_projects, max_generations_per_month, max_ai_credits_per_month, max_file_size_mb, can_use_custom_models, can_export_projects, can_use_advanced_agents, priority_support) VALUES
('free', 2, 1, 5, 0.00, 10, false, true, false, false),
('starter', 5, 3, 20, 0.00, 50, false, true, false, false),
('professional', -1, -1, 100, 5.00, 200, true, true, true, false),
('business', -1, -1, 500, 15.00, 500, true, true, true, true),
('enterprise', -1, -1, -1, -1, 1000, true, true, true, true)
ON CONFLICT (subscription_tier) DO NOTHING;

-- 6. Индексы для производительности
CREATE INDEX IF NOT EXISTS idx_profiles_email ON profiles(email);
CREATE INDEX IF NOT EXISTS idx_profiles_subscription_tier ON profiles(subscription_tier);
CREATE INDEX IF NOT EXISTS idx_projects_user_id ON projects(user_id);
CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status);
CREATE INDEX IF NOT EXISTS idx_projects_created_at ON projects(created_at);
CREATE INDEX IF NOT EXISTS idx_api_usage_user_id ON api_usage_log(user_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_timestamp ON api_usage_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_user_api_keys_user_id ON user_api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_user_api_keys_provider_id ON user_api_keys(provider_id);

-- Готово! Теперь можно запускать сервер
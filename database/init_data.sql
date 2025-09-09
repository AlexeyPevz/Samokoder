-- =============================================
-- Инициализация начальных данных для Самокодер
-- =============================================

-- Создаем функцию для автоматического создания профиля пользователя
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.profiles (id, email, full_name, created_at, updated_at)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email),
        NOW(),
        NOW()
    );
    
    -- Создаем настройки пользователя по умолчанию
    INSERT INTO public.user_settings (user_id, created_at, updated_at)
    VALUES (NEW.id, NOW(), NOW());
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Создаем триггер для автоматического создания профиля при регистрации
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Создаем функцию для обновления профиля при изменении данных в auth.users
CREATE OR REPLACE FUNCTION public.handle_user_update()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE public.profiles
    SET 
        email = NEW.email,
        full_name = COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email),
        updated_at = NOW()
    WHERE id = NEW.id;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Создаем триггер для обновления профиля
DROP TRIGGER IF EXISTS on_auth_user_updated ON auth.users;
CREATE TRIGGER on_auth_user_updated
    AFTER UPDATE ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_user_update();

-- Создаем функцию для получения статистики пользователя
CREATE OR REPLACE FUNCTION get_user_stats(user_uuid UUID)
RETURNS JSON AS $$
DECLARE
    result JSON;
BEGIN
    SELECT json_build_object(
        'total_projects', COUNT(*),
        'active_projects', COUNT(*) FILTER (WHERE status IN ('draft', 'generating')),
        'completed_projects', COUNT(*) FILTER (WHERE status = 'completed'),
        'total_generations', (
            SELECT COUNT(*) FROM api_usage_log 
            WHERE user_id = user_uuid AND operation_type = 'generation'
        ),
        'total_tokens_used', (
            SELECT COALESCE(SUM(total_tokens), 0) FROM api_usage_log 
            WHERE user_id = user_uuid
        ),
        'total_cost_usd', (
            SELECT COALESCE(SUM(cost_usd), 0) FROM api_usage_log 
            WHERE user_id = user_uuid
        ),
        'api_keys_count', (
            SELECT COUNT(*) FROM user_api_keys 
            WHERE user_id = user_uuid AND is_active = true
        )
    ) INTO result
    FROM projects 
    WHERE user_id = user_uuid;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Создаем функцию для получения популярных моделей
CREATE OR REPLACE FUNCTION get_popular_models(limit_count INTEGER DEFAULT 10)
RETURNS TABLE (
    model_id UUID,
    model_name TEXT,
    display_name TEXT,
    provider_name TEXT,
    usage_count BIGINT,
    is_free BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        am.id,
        am.model_name,
        am.display_name,
        ap.name as provider_name,
        COUNT(aul.id) as usage_count,
        am.is_free
    FROM ai_models am
    JOIN ai_providers ap ON am.provider_id = ap.id
    LEFT JOIN api_usage_log aul ON aul.model_name = am.model_name
    WHERE am.is_active = true AND ap.is_active = true
    GROUP BY am.id, am.model_name, am.display_name, ap.name, am.is_free
    ORDER BY usage_count DESC, am.is_free DESC
    LIMIT limit_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Создаем функцию для очистки старых данных
CREATE OR REPLACE FUNCTION cleanup_old_data()
RETURNS VOID AS $$
BEGIN
    -- Удаляем старые логи использования (старше 1 года)
    DELETE FROM api_usage_log 
    WHERE timestamp < NOW() - INTERVAL '1 year';
    
    -- Архивируем старые проекты (старше 6 месяцев без активности)
    UPDATE projects 
    SET status = 'archived', archived_at = NOW()
    WHERE status != 'archived' 
    AND updated_at < NOW() - INTERVAL '6 months'
    AND status NOT IN ('generating');
    
    -- Удаляем неактивные API ключи (старше 1 года без использования)
    DELETE FROM user_api_keys 
    WHERE is_active = false 
    AND last_used_at < NOW() - INTERVAL '1 year';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Создаем представление для аналитики использования
CREATE OR REPLACE VIEW user_usage_analytics AS
SELECT 
    p.id as user_id,
    p.email,
    p.subscription_tier,
    COUNT(DISTINCT pr.id) as total_projects,
    COUNT(DISTINCT pr.id) FILTER (WHERE pr.status = 'completed') as completed_projects,
    COUNT(DISTINCT aul.id) as total_api_calls,
    COALESCE(SUM(aul.total_tokens), 0) as total_tokens_used,
    COALESCE(SUM(aul.cost_usd), 0) as total_cost_usd,
    COUNT(DISTINCT uak.id) as active_api_keys,
    MAX(aul.timestamp) as last_activity
FROM profiles p
LEFT JOIN projects pr ON p.id = pr.user_id
LEFT JOIN api_usage_log aul ON p.id = aul.user_id
LEFT JOIN user_api_keys uak ON p.id = uak.user_id AND uak.is_active = true
GROUP BY p.id, p.email, p.subscription_tier;

-- Создаем представление для статистики провайдеров
CREATE OR REPLACE VIEW provider_usage_stats AS
SELECT 
    ap.name as provider_name,
    ap.display_name,
    COUNT(DISTINCT aul.user_id) as unique_users,
    COUNT(aul.id) as total_calls,
    COALESCE(SUM(aul.total_tokens), 0) as total_tokens,
    COALESCE(SUM(aul.cost_usd), 0) as total_cost,
    COALESCE(AVG(aul.cost_usd), 0) as avg_cost_per_call,
    COUNT(DISTINCT am.model_name) as models_used
FROM ai_providers ap
LEFT JOIN ai_models am ON ap.id = am.provider_id
LEFT JOIN api_usage_log aul ON aul.provider_name = ap.name
WHERE ap.is_active = true
GROUP BY ap.id, ap.name, ap.display_name
ORDER BY total_calls DESC;

-- Создаем индексы для производительности аналитических запросов
CREATE INDEX IF NOT EXISTS idx_api_usage_log_user_timestamp ON api_usage_log(user_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_api_usage_log_provider_model ON api_usage_log(provider_name, model_name);
CREATE INDEX IF NOT EXISTS idx_projects_user_status ON projects(user_id, status);

-- Создаем функцию для получения рекомендаций моделей для пользователя
CREATE OR REPLACE FUNCTION get_model_recommendations(user_uuid UUID)
RETURNS TABLE (
    model_id UUID,
    model_name TEXT,
    display_name TEXT,
    provider_name TEXT,
    recommendation_score INTEGER,
    reason TEXT
) AS $$
BEGIN
    RETURN QUERY
    WITH user_usage AS (
        SELECT 
            provider_name,
            model_name,
            COUNT(*) as usage_count,
            SUM(cost_usd) as total_cost
        FROM api_usage_log 
        WHERE user_id = user_uuid
        GROUP BY provider_name, model_name
    ),
    user_keys AS (
        SELECT DISTINCT provider_id
        FROM user_api_keys 
        WHERE user_id = user_uuid AND is_active = true
    )
    SELECT 
        am.id,
        am.model_name,
        am.display_name,
        ap.name as provider_name,
        CASE 
            WHEN am.is_free THEN 100
            WHEN uk.provider_id IS NOT NULL THEN 80
            WHEN uu.usage_count > 0 THEN 60
            ELSE 20
        END as recommendation_score,
        CASE 
            WHEN am.is_free THEN 'Бесплатная модель'
            WHEN uk.provider_id IS NOT NULL THEN 'У вас есть API ключ для этого провайдера'
            WHEN uu.usage_count > 0 THEN 'Вы уже использовали эту модель'
            ELSE 'Популярная модель'
        END as reason
    FROM ai_models am
    JOIN ai_providers ap ON am.provider_id = ap.id
    LEFT JOIN user_usage uu ON uu.provider_name = ap.name AND uu.model_name = am.model_name
    LEFT JOIN user_keys uk ON uk.provider_id = am.provider_id
    WHERE am.is_active = true AND ap.is_active = true
    ORDER BY recommendation_score DESC, am.is_free DESC
    LIMIT 10;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Создаем функцию для проверки доступности функции для пользователя
CREATE OR REPLACE FUNCTION check_feature_access(user_uuid UUID, feature_name TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    user_tier TEXT;
    has_access BOOLEAN := false;
BEGIN
    -- Получаем тариф пользователя
    SELECT subscription_tier INTO user_tier FROM profiles WHERE id = user_uuid;
    
    -- Проверяем доступ к функции
    CASE feature_name
        WHEN 'custom_models' THEN
            SELECT can_use_custom_models INTO has_access 
            FROM subscription_limits WHERE subscription_tier = user_tier;
        WHEN 'export_projects' THEN
            SELECT can_export_projects INTO has_access 
            FROM subscription_limits WHERE subscription_tier = user_tier;
        WHEN 'advanced_agents' THEN
            SELECT can_use_advanced_agents INTO has_access 
            FROM subscription_limits WHERE subscription_tier = user_tier;
        WHEN 'priority_support' THEN
            SELECT priority_support INTO has_access 
            FROM subscription_limits WHERE subscription_tier = user_tier;
        ELSE
            has_access := false;
    END CASE;
    
    RETURN has_access;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
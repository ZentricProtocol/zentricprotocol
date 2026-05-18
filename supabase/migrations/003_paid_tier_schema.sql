-- =============================================================================
-- Migration 003: Paid-tier schema (api_keys, subscriptions, reports)
-- Applied to project bbgpmfepfkpqhwhloudy on 2026-05-18.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------------------------
-- subscriptions
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.subscriptions (
  id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                 UUID        REFERENCES auth.users(id) ON DELETE CASCADE,
  stripe_subscription_id  TEXT        UNIQUE NOT NULL,
  stripe_customer_id      TEXT        UNIQUE,
  status                  TEXT        NOT NULL DEFAULT 'incomplete',
  plan                    TEXT        NOT NULL DEFAULT 'growth',
  current_period_end      TIMESTAMPTZ,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id            ON public.subscriptions (user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_customer_id ON public.subscriptions (stripe_customer_id);

ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view own subscription" ON public.subscriptions;
CREATE POLICY "Users can view own subscription"
  ON public.subscriptions FOR SELECT
  USING (auth.uid() = user_id);

-- -----------------------------------------------------------------------------
-- api_keys
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.api_keys (
  id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  key_hash             TEXT        NOT NULL UNIQUE,
  tier                 TEXT        NOT NULL DEFAULT 'growth',
  requests_this_month  INTEGER     NOT NULL DEFAULT 0,
  revoked_at           TIMESTAMPTZ,
  last_used_at         TIMESTAMPTZ,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON public.api_keys (key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id  ON public.api_keys (user_id);

ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view own keys"   ON public.api_keys;
DROP POLICY IF EXISTS "Users can insert own keys" ON public.api_keys;
DROP POLICY IF EXISTS "Users can update own keys" ON public.api_keys;

CREATE POLICY "Users can view own keys"
  ON public.api_keys FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own keys"
  ON public.api_keys FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own keys"
  ON public.api_keys FOR UPDATE
  USING (auth.uid() = user_id);

-- -----------------------------------------------------------------------------
-- reports
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.reports (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  report_id   TEXT        NOT NULL UNIQUE,
  user_id     UUID        REFERENCES auth.users(id) ON DELETE SET NULL,
  verdict     TEXT        NOT NULL,
  sha256      TEXT        NOT NULL,
  latency_ms  INTEGER,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_reports_user_id    ON public.reports (user_id);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON public.reports (created_at DESC);

ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view own reports" ON public.reports;
CREATE POLICY "Users can view own reports"
  ON public.reports FOR SELECT
  USING (auth.uid() = user_id);

-- -----------------------------------------------------------------------------
-- RPC: increment_api_key_usage(p_key_hash text)
-- Atomic increment by hash; matches the call in api/v1/analyze.js
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.increment_api_key_usage(p_key_hash TEXT)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE public.api_keys
  SET requests_this_month = requests_this_month + 1,
      last_used_at        = now()
  WHERE key_hash = p_key_hash
    AND revoked_at IS NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.increment_api_key_usage(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.increment_api_key_usage(TEXT) TO service_role;

-- Same pattern for the free tier (called from analyze.js)
CREATE OR REPLACE FUNCTION public.increment_free_key_usage(p_key_hash TEXT)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  current_bucket TEXT := to_char(now(), 'YYYY-MM');
BEGIN
  UPDATE public.free_api_keys
  SET requests_this_month = CASE
        WHEN month_bucket = current_bucket THEN requests_this_month + 1
        ELSE 1
      END,
      month_bucket = current_bucket,
      last_used_at = now()
  WHERE key_hash = p_key_hash;
END;
$$;

REVOKE ALL ON FUNCTION public.increment_free_key_usage(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.increment_free_key_usage(TEXT) TO service_role;

-- -----------------------------------------------------------------------------
-- RPC: reset_monthly_usage()
-- Called by Vercel Cron on the 1st of each month at 00:05 UTC
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.reset_monthly_usage()
RETURNS TABLE (paid_reset INTEGER, free_reset INTEGER)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_paid INTEGER;
  v_free INTEGER;
  current_bucket TEXT := to_char(now(), 'YYYY-MM');
BEGIN
  WITH upd AS (
    UPDATE public.api_keys
    SET requests_this_month = 0
    WHERE requests_this_month > 0
    RETURNING 1
  )
  SELECT count(*) INTO v_paid FROM upd;

  WITH upd AS (
    UPDATE public.free_api_keys
    SET requests_this_month = 0,
        month_bucket        = current_bucket
    WHERE requests_this_month > 0
       OR month_bucket <> current_bucket
    RETURNING 1
  )
  SELECT count(*) INTO v_free FROM upd;

  RETURN QUERY SELECT v_paid, v_free;
END;
$$;

REVOKE ALL ON FUNCTION public.reset_monthly_usage() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.reset_monthly_usage() TO service_role;

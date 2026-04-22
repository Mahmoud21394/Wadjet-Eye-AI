-- ══════════════════════════════════════════════════════════════════
--  Migration v5.3 — Add image_url to news_articles
--  Adds the image_url column that news-ingestion.js expects.
--  Safe to run multiple times (IF NOT EXISTS guard).
-- ══════════════════════════════════════════════════════════════════

DO $$
BEGIN
  -- Add image_url column to news_articles if not present
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'news_articles' AND column_name = 'image_url'
  ) THEN
    ALTER TABLE news_articles ADD COLUMN image_url TEXT;
    COMMENT ON COLUMN news_articles.image_url IS 'Optional thumbnail/preview image URL from RSS feed';
  END IF;

  -- Add asset_inventory.name if missing (required NOT NULL in schema but may be
  -- absent in older deployments)
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'asset_inventory' AND column_name = 'name'
  ) THEN
    ALTER TABLE asset_inventory ADD COLUMN name TEXT NOT NULL DEFAULT 'Unknown Asset';
  END IF;
END $$;

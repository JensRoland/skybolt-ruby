# frozen_string_literal: true

require "minitest/autorun"
require "base64"
require_relative "../lib/skybolt/cache_digest"

# Tests for CacheDigest (Cuckoo filter implementation)
#
# These tests use cross-language test vectors to ensure compatibility
# with the JavaScript implementation.
class TestCacheDigest < Minitest::Test
  # This digest was created by the JavaScript implementation with these assets:
  # - src/css/critical.css:B20ictSB
  # - src/css/main.css:DfFbFQk_
  # - src/js/app.js:DW873Fox
  # - skybolt-launcher:ptJmv_9y
  VALID_DIGEST = "AQAEAAQAAAAAAAAAAAXNB-UAAAAACT4NhgAAAAAAAAAAAAAAAA"

  # Cross-language test vectors for FNV-1a hash
  # These values must match the JavaScript implementation exactly
  def test_fnv1a_matches_javascript
    test_cases = [
      ["src/css/critical.css:abc123", 821_208_812],
      ["src/css/main.css:def456", 26_790_494],
      ["skybolt-launcher:xyz789", 452_074_441],
      ["123", 1_916_298_011],
      ["", 2_166_136_261], # Empty string returns offset basis
      ["a", 3_826_002_220],
      ["test", 2_949_673_445]
    ]

    test_cases.each do |input, expected|
      assert_equal expected, Skybolt::CacheDigest.fnv1a(input),
                   "FNV-1a hash mismatch for '#{input}'"
    end
  end

  # Test fingerprint generation
  def test_fingerprint_in_valid_range
    # Fingerprint should be in range [1, 4095] (12 bits, never 0)
    test_cases = [
      "src/css/critical.css:abc123",
      "src/css/main.css:def456",
      "skybolt-launcher:xyz789"
    ]

    test_cases.each do |input|
      fp = Skybolt::CacheDigest.fingerprint(input)
      assert fp >= 1, "Fingerprint should be >= 1"
      assert fp <= 4095, "Fingerprint should be <= 4095"
    end
  end

  # Test fingerprint never returns 0
  def test_fingerprint_never_zero
    1000.times do |i|
      fp = Skybolt::CacheDigest.fingerprint("test-#{i}")
      refute_equal 0, fp, "Fingerprint should never be 0"
    end
  end

  # Test alternate bucket calculation is reversible
  def test_alternate_bucket_reversible
    num_buckets = 16 # Power of 2

    num_buckets.times do |bucket|
      (1..100).each do |fp|
        alt = Skybolt::CacheDigest.compute_alternate_bucket(bucket, fp, num_buckets)
        original = Skybolt::CacheDigest.compute_alternate_bucket(alt, fp, num_buckets)

        assert_equal bucket, original,
                     "Alternate bucket should be reversible: bucket=#{bucket}, fp=#{fp}"
      end
    end
  end

  # Test parsing a valid digest from JavaScript
  def test_parse_valid_digest
    cd = Skybolt::CacheDigest.from_base64(VALID_DIGEST)

    assert cd.valid?

    # These should be found
    assert cd.lookup("src/css/critical.css:B20ictSB")
    assert cd.lookup("src/css/main.css:DfFbFQk_")
    assert cd.lookup("src/js/app.js:DW873Fox")
    assert cd.lookup("skybolt-launcher:ptJmv_9y")

    # These should NOT be found (different hashes)
    refute cd.lookup("src/css/critical.css:DIFFERENT")
    refute cd.lookup("src/css/main.css:DIFFERENT")
    refute cd.lookup("nonexistent:asset")
  end

  # Test parsing empty digest
  def test_parse_empty_digest
    cd = Skybolt::CacheDigest.from_base64("")
    refute cd.valid?
    refute cd.lookup("anything")
  end

  # Test parsing invalid base64
  def test_parse_invalid_base64
    cd = Skybolt::CacheDigest.from_base64("not-valid-base64!!!")
    refute cd.valid?
  end

  # Test parsing digest with wrong version
  def test_parse_wrong_version
    # Version 2 header (invalid)
    cd = Skybolt::CacheDigest.from_base64(Base64.strict_encode64("\x02\x00\x04\x00\x00"))
    refute cd.valid?
  end

  # Test parsing truncated digest
  def test_parse_truncated_digest
    # Too short
    cd = Skybolt::CacheDigest.from_base64(Base64.strict_encode64("\x01\x00"))
    refute cd.valid?
  end

  # Test URL-safe base64 handling
  def test_url_safe_base64
    # Same digest with URL-safe characters (- instead of +, _ instead of /)
    cd = Skybolt::CacheDigest.from_base64(VALID_DIGEST)

    assert cd.valid?
    assert cd.lookup("src/css/critical.css:B20ictSB")
  end
end

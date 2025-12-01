# frozen_string_literal: true

require "base64"

module Skybolt
  # Cache Digest implementation using a Cuckoo filter.
  #
  # This is a read-only parser for digests created by the JavaScript client.
  # It's used to determine which assets the client already has cached.
  class CacheDigest
    FINGERPRINT_BITS = 12
    BUCKET_SIZE = 4

    # Create a CacheDigest from a base64-encoded string.
    #
    # @param digest [String] URL-safe base64-encoded digest from sb_digest cookie
    # @return [CacheDigest] A valid or invalid CacheDigest instance
    def self.from_base64(digest)
      new(digest)
    end

    # Compute FNV-1a hash of a string (32-bit).
    #
    # @param str [String] Input string
    # @return [Integer] 32-bit hash value
    def self.fnv1a(str)
      hash = 2166136261
      str.each_byte do |byte|
        hash ^= byte
        hash = (hash * 16777619) & 0xFFFFFFFF
      end
      hash
    end

    # Compute fingerprint for Cuckoo filter.
    #
    # @param str [String] Input string
    # @return [Integer] Fingerprint in range [1, 4095]
    def self.fingerprint(str)
      hash = fnv1a(str)
      fp = hash & ((1 << FINGERPRINT_BITS) - 1)
      fp == 0 ? 1 : fp
    end

    # Compute alternate bucket index for Cuckoo filter.
    #
    # @param bucket [Integer] Current bucket index
    # @param fp [Integer] Fingerprint value
    # @param num_buckets [Integer] Total number of buckets
    # @return [Integer] Alternate bucket index
    def self.compute_alternate_bucket(bucket, fp, num_buckets)
      fp_hash = fnv1a(fp.to_s)
      bucket_mask = num_buckets - 1
      offset = (fp_hash | 1) & bucket_mask
      (bucket ^ offset) & bucket_mask
    end

    # @return [Boolean] Whether this is a valid digest
    attr_reader :valid
    alias valid? valid

    # Check if an item exists in the digest.
    #
    # @param item [String] Item to look up (e.g., "src/css/main.css:hash123")
    # @return [Boolean] True if item might be in the filter (may have false positives)
    def lookup(item)
      return false unless @valid

      fp = self.class.fingerprint(item)
      i1 = primary_bucket(item)
      i2 = self.class.compute_alternate_bucket(i1, fp, @num_buckets)
      bucket_contains?(i1, fp) || bucket_contains?(i2, fp)
    end

    private

    def initialize(digest)
      @valid = false
      @buckets = []
      @num_buckets = 0

      parse_digest(digest)
    end

    def parse_digest(digest)
      return if digest.nil? || digest.empty?

      # Handle URL-safe base64
      normalized = digest.tr("-_", "+/")
      # Add padding if needed
      normalized += "=" * ((4 - normalized.length % 4) % 4)

      begin
        data = Base64.strict_decode64(normalized)
      rescue ArgumentError
        return
      end

      return if data.bytesize < 5

      # Check version (must be 1)
      return if data.getbyte(0) != 1

      @num_buckets = (data.getbyte(1) << 8) | data.getbyte(2)
      num_fingerprints = @num_buckets * BUCKET_SIZE

      @buckets = []
      num_fingerprints.times do |i|
        offset = 5 + i * 2
        if offset + 1 < data.bytesize
          @buckets << ((data.getbyte(offset) << 8) | data.getbyte(offset + 1))
        else
          @buckets << 0
        end
      end

      @valid = true
    end

    def primary_bucket(str)
      self.class.fnv1a(str) % @num_buckets
    end

    def bucket_contains?(bucket_index, fp)
      offset = bucket_index * BUCKET_SIZE
      BUCKET_SIZE.times do |i|
        return true if @buckets[offset + i] == fp
      end
      false
    end
  end
end

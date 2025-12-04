# Merge Conflict Resolution Decisions

## Date: 2024-12-19
## Branch: post-pr-fixes merging with remotes/fork/main

### File: `tables/requests_log/requests_log_mapper.go`

1. **Imports (lines 8-21)**: Use a combination of ours and theirs, but omit any duplicate lines.
   - Decision: Combine imports, keep unique ones from both

2. **Helper types/functions (lines 34-91)**: Use ours.
   - Decision: Keep `flexibleInt64` type and `sanitizeURL` function

3. **Map function - logging.Entry case (lines 98-102)**: Use ours.
   - Decision: No case for `*logging.Entry`

4. **mapFromSDKType - log name filtering (lines 111-125)**: Use ours.
   - Decision: Keep log name filtering and early exit checks

5. **mapFromSDKType - Trace/SpanId comments (lines 135-144)**: Use ours.
   - Decision: Keep comments and formatting from ours

6. **mapFromSDKType - JsonPayload handling (lines 159-172)**: Use ours.
   - Decision: Keep direct type assertion (note: may need to reconsider if this causes panics)

7. **mapFromSDKType - RemoteIp/StatusDetails (lines 182-210)**: Use whichever is the better practice.
   - Decision: Use theirs (safe type assertions with `ok` checks) - better practice

8. **mapFromSDKType - EnforcedSecurityPolicy (lines 186-234)**: Use theirs.
   - Decision: Use safe extraction, handle `PreconfiguredExprId` as single string

9. **mapFromSDKType - PreviewSecurityPolicy (lines 239-275)**: Use theirs.
   - Decision: Use safe extraction, handle `PreconfiguredExprId` as single string

10. **mapFromSDKType - HttpRequest mapping (lines 278-347)**: Use ours.
    - Decision: Keep URL sanitization, int64 for sizes, simpler structure

11. **mapFromSDKType - SecurityPolicyRequestData (lines 298-318)**: Use theirs.
    - Decision: Add SecurityPolicyRequestData mapping with safe extraction

12. **mapFromBucketJson - error message and filtering (lines 355-374)**: Use theirs.
    - Decision: Use their error message, remove log name filtering (they handle it differently)

13. **mapFromBucketJson - Resource mapping (lines 382-419)**: Use whatever combination is best, but do sanitize URLs.
    - Decision: Combine - use their nil checks and safe Labels handling, but add URL sanitization

14. **mapFromBucketJson - JsonPayload mapping (lines 387-449)**: Use ours.
    - Decision: Keep our direct field access and URL sanitization

15. **requestsLog struct - TraceSampled (lines 526-529)**: Use theirs.
    - Decision: Add `TraceSampled bool` field

16. **jsonPayload struct (lines 541-549)**: Use theirs.
    - Decision: Use single `requestLogSecurityPolicy` type, add `CacheId` and `CompressionStatus`

17. **httpRequest struct (lines 555-605)**: Use ours, but include any missing fields.
    - Decision: Keep `flexibleInt64` for sizes, but add CacheHit/CacheValidatedWithOriginServer fields

18. **requestLogSecurityPolicy types (lines 570-631)**: Use theirs.
    - Decision: Use single unified type with all fields, include Recaptcha tokens

19. **Additional helper types (lines 638-657)**: Use theirs.
    - Decision: Add all helper types: RecaptchaToken, RateLimitAction, ThreatIntelligence, AddressGroup


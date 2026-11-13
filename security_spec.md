# Security Specification: WP Sentinel Firestore Security

## 1. Data Invariants
1. **User Isolation**: A user can only access, create, update, or delete documents within their own `/users/{userId}` hierarchy.
2. **Owner Identity Consistency**: Any document created within `/users/{userId}/...` must have `userId == request.auth.uid` and match the path parameter `{userId}`.
3. **No Cross-User Access**: Unauthenticated users or other authenticated users cannot read or write to `/users/{userId}` or any subcollection (`scans`, `sites`).
4. **Immutable Identity**: Once created, `userId` and `id` fields cannot be altered.
5. **Payload Bounds**: All string fields must adhere strictly to length limits to prevent resource exhaustion attacks.

## 2. The "Dirty Dozen" Threat Vectors & Reject Payloads
1. **Unauthenticated Read on Scans**: An unauthenticated user querying `/users/{victimId}/scans`. (Rejected by `request.auth != null`)
2. **Cross-Tenant Scan Theft**: Authenticated User B attempts to read `/users/UserA/scans/scan123`. (Rejected by `request.auth.uid == userId`)
3. **Ghost Identity Write**: User B attempts to create a scan under `/users/UserB/scans/scan1` but sets `userId: "UserA"`. (Rejected by `incoming().userId == request.auth.uid`)
4. **Path Traversal / Junk Doc ID**: An attacker attempts to create document with 2KB junk characters in `{scanId}`. (Rejected by `isValidId(scanId)`)
5. **Ghost Field Poisoning**: An attacker adds `isAdmin: true` or malicious executable blob into `Scan` document. (Rejected by strict schema checks)
6. **Negative or Overflow Score Injection**: An attacker attempts to set `score: -999` or `score: 99999`. (Rejected by `incoming().score >= 0 && incoming().score <= 100`)
7. **Cross-User Site Mutation**: User B attempts to delete User A's monitored site `/users/UserA/sites/site1`. (Rejected by `request.auth.uid == userId`)
8. **Spoofed User Registration**: User B attempts to create `/users/UserA` profile. (Rejected by `request.auth.uid == userId`)
9. **Blanket Query Scraping**: Malicious client attempts `db.collectionGroup('scans').get()` to list everyone's vulnerability findings. (Rejected by default-deny catch-all)
10. **Immutable Field Tampering**: User attempts to update a scan's `userId` or `id`. (Rejected by immutability enforcement)
11. **Oversized String DoS**: User submits a `targetUrl` with 50,000 characters. (Rejected by `targetUrl.size() <= 512`)
12. **Unauthenticated Site Verification Injection**: An attacker tries to post verified sites directly. (Rejected by authentication and ownership constraints)

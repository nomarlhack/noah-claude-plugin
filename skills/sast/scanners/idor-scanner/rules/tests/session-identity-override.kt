package test
import org.springframework.web.bind.annotation.*
data class RvpReq(val accountId: Long?, val types: List<String>?)

@RestController
@RequestMapping("/common", "/guest/public/common")
class C(val svc: Svc) {
    @GetMapping("/x")
    suspend fun getAll(
        @Valid request: RvpReq,
        @RequestHeader(value = "account-id", required = false) accountIdHeader: Long?,
    ): Any {
        // ruleid: noah-kotlin-idor-session-identity-override
        val accountId = accountIdHeader ?: request.accountId
        return svc.getAll(accountId!!)
    }
    @DeleteMapping("/x")
    suspend fun delete(
        @RequestParam(value = "accountId", required = false) accountIdParam: Long?,
        @RequestHeader(value = "account-id", required = false) accountIdHeader: Long?,
    ) {
        // ruleid: noah-kotlin-idor-session-identity-override
        val accountId = accountIdParam ?: accountIdHeader
        svc.delete(accountId!!)
    }
    @GetMapping("/safe1")
    suspend fun safe1(@RequestHeader("account-id") h: Long): Any {
        // ok: noah-kotlin-idor-session-identity-override
        val accountId = h
        return svc.getAll(accountId)
    }
    @GetMapping("/safe2")
    suspend fun safe2(@RequestParam storeId: Long, @RequestParam(required=false) fb: Long?): Any {
        // ok: noah-kotlin-idor-session-identity-override
        val other = fb ?: storeId
        return svc.byStore(storeId + other)
    }
}

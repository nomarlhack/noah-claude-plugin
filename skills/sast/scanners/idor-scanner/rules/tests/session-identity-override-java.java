package test;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;
import java.util.Optional;
class RvpReq { Long accountId; public Long getAccountId(){return accountId;} }
@RestController
class CJ {
    private final Svc svc; CJ(Svc s){svc=s;}
    @DeleteMapping("/x")
    public void delete(@RequestParam(required=false) Long accountIdParam,
                       @RequestHeader(value="account-id", required=false) Long accountIdHeader) {
        // ruleid: noah-java-idor-session-identity-override
        Long accountId = accountIdParam != null ? accountIdParam : accountIdHeader;
        svc.delete(accountId);
    }
    @GetMapping("/x")
    public Object getAll(@Valid RvpReq request,
                         @RequestHeader(value="account-id", required=false) Long accountIdHeader) {
        // ruleid: noah-java-idor-session-identity-override
        Long accountId = accountIdHeader != null ? accountIdHeader : request.getAccountId();
        return svc.getAll(accountId);
    }
    @GetMapping("/y")
    public Object y(@RequestParam(required=false) Long accountIdParam,
                    @RequestHeader(value="account-id", required=false) Long accountIdHeader) {
        // ruleid: noah-java-idor-session-identity-override
        Long accountId = Optional.ofNullable(accountIdParam).orElse(accountIdHeader);
        return svc.getAll(accountId);
    }
    @GetMapping("/safe1")
    public Object safe1(@RequestHeader("account-id") Long accountIdHeader) {
        // ok: noah-java-idor-session-identity-override
        Long accountId = accountIdHeader;
        return svc.getAll(accountId);
    }
    @GetMapping("/safe2")
    public Object safe2(@RequestParam Long storeId, @RequestParam(required=false) Long fb) {
        // ok: noah-java-idor-session-identity-override
        Long s = fb != null ? fb : storeId;
        return svc.byStore(s);
    }
}

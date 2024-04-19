// your package path

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RateLimitingInterceptor implements HandlerInterceptor {

    private static final String RATE_LIMITER_KEY_PREFIX = ""; // Add your redis key
    private static final int MAX_REQUESTS_PER_MINUTE = 20; // modify as per your usecase
    private static final long WINDOW_SIZE_MINUTES = 1; // window size in minutes

    private final RedisTemplate<String, String> redisTemplate;

    @Autowired
    public RateLimitingInterceptor(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public boolean preHandle(
        HttpServletRequest request,
        HttpServletResponse response,
        Object handler) throws Exception {
        if (handler instanceof HandlerMethod) {
            String apiEndpoint = request.getRequestURI();
            String ipAddress = request.getRemoteAddr();

            if (shouldApplyRateLimiting(apiEndpoint, ipAddress)) {
                String rateLimiterKey = getRateLimiterKey(apiEndpoint, ipAddress);
                try {
                    long count = redisTemplate.opsForValue()
                                              .increment(rateLimiterKey, 1);

                    if (count == 1) {
                        redisTemplate.expire(rateLimiterKey, WINDOW_SIZE_MINUTES, TimeUnit.MINUTES);
                    }
                    if (count > MAX_REQUESTS_PER_MINUTE) {
                        response.sendError(HttpStatus.TOO_MANY_REQUESTS.value(), "Rate limit exceeded");
                        return false;
                    }
                } catch (Exception ex) {
                    log.error("Redis exception:", ex);
                }
            }
        }

        return true;
    }

    private boolean shouldApplyRateLimiting(
        String apiEndpoint,
        String ipAddress) {
        if (apiEndpoint.contains("ping")) {
            return false;
        }

        // Add conditions here to determine which API endpoints and IP addresses should be rate-limited
        return true;
    }

    private String getRateLimiterKey(
        String apiEndpoint,
        String ipAddress) {
        return RATE_LIMITER_KEY_PREFIX + ":" + apiEndpoint + ":" + ipAddress;
    }
}

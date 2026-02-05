# Global Filters / Interceptors Check

Purpose: determine whether global input filtering or request guards exist before analyzing injection/XSS/data issues.

## What to check
- WebFlux: `WebFilter`, `SecurityWebFilterChain`, `ServerWebExchange` filters
- Servlet: `OncePerRequestFilter`, `Filter`, `FilterRegistrationBean`
- Spring MVC: `HandlerInterceptor` / `WebMvcConfigurer#addInterceptors`

## Quick search
```bash
rg -n "WebFilter|OncePerRequestFilter|Filter\\b|HandlerInterceptor|WebMvcConfigurer|SecurityWebFilterChain" src/main
```

## Output
Record in task metadata:
- `global_filter_present: true|false`
- `global_filter_notes: <short summary>`

If filters exist, note whether they perform **input validation** or **only auth/CSP**.

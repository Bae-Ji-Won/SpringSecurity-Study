package me.benny.practice.spring.security.config;

import lombok.RequiredArgsConstructor;
import me.benny.practice.spring.security.user.User;
import me.benny.practice.spring.security.user.UserService;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Security 설정 Config
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter{

    private final UserService userService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // basic authentication
        http.httpBasic().disable(); // basic authentication filter 비활성화
        // csrf
        http.csrf();            // csrf 외부 접근 차단
        // remember-me
        http.rememberMe();      // 사용자 데이터 기억
        // anonymous
        http.anonymous().principal("방문자");      // 인증하지 않은 사용자 접근 허용(방문자 신분으로 header에 저장)
        // authorization
        http.authorizeRequests()        // 인가 설정
                .antMatchers("/", "/home", "/signup").permitAll()  // .antMatchers() : 경로 지정, permitAll() : 모든 인원에게 권한 허용
                .antMatchers("/note").hasRole("USER")    
                .antMatchers("/admin").hasRole("ADMIN")     // admin 페이지는 ADMIN 롤을 가진 유저에게만 허용
                .antMatchers(HttpMethod.POST, "/notice").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/notice").hasRole("ADMIN")
                .anyRequest().authenticated();          // 위에서 설정한 페이지를 제외한 나머지에서는 인증이 된 사람만 접근 가능
                                                        // anyRequest() : 나머지 값, authenticated() : 인증이 된 사람만 접근 가능
        // login
        http.formLogin()        // 로그인 페이지 설정
                .loginPage("/login")        // 로그인 페이지 URL 주소 지정
                .defaultSuccessUrl("/")     // 로그인 성공시 이동할 URL 주소 지정
                .permitAll(); // 모든 사용자에게 허용
        // logout
        http.logout()           // 로그아웃 페이지 설정
//              .logoutUrl("/logout")   로그아웃은 따로 페이지가 필요없으므로 아래의 코드 사용
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))  // 로그아웃은 Post 형식으로 오기 때문에 따로 페이지가 없으므로 로그아웃 요청을 "/logout" URL로 지정
                .logoutSuccessUrl("/");      // 로그아웃 성공시 이동할 URL 주소 지정
    }

    @Override
    public void configure(WebSecurity web) {
        // ignoring() : springsecurity의 보호를 받지 않을 파일 설정
        // 정적 리소스 spring security 대상에서 제외
        // web.ignoring().antMatchers("/images/**", "/css/**"); // 아래 코드와 같은 코드입니다.
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());    // Static폴더에 있는 파일들을 ignoring 시키겠다
    }

    /**
     * UserDetailsService 구현
     *
     * @return UserDetailsService
     */
    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        return username -> {
            User user = userService.findByUsername(username);
            if (user == null) {
                throw new UsernameNotFoundException(username);
            }
            return user;
        };
    }
}

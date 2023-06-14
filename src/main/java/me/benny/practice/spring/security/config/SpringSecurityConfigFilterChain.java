package me.benny.practice.spring.security.config;


import lombok.RequiredArgsConstructor;
import me.benny.practice.spring.security.user.User;
import me.benny.practice.spring.security.user.UserService;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SpringSecurityConfigFilterChain {
    // FilterChain
    private final UserService userService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                // basic authentication filter disable
                .httpBasic().disable()
                // 외부 요청 금지
                .csrf()
                .and()
                // 사용자 기억
                .rememberMe()
                .and()
                // 경로 권한 설정
                .authorizeRequests()
                    .antMatchers("/","/home","/signup").permitAll()
                    .antMatchers("/note").hasRole("USER")
                    .antMatchers("/admin").hasRole("ADMIN")
                    .antMatchers(HttpMethod.GET,"/notice").authenticated()      // notice GET url은 인증받은 사람 접근 가능
                    .antMatchers(HttpMethod.POST,"/notice").hasRole("ADMIN")    // notice POST url은 관리자만 접근 가능
                    .antMatchers().authenticated()
                .and()
                // 로그인 관련 필터 설정
                .formLogin()
                    .loginPage("/login")
                    .defaultSuccessUrl("/")
                    .permitAll()
                .and()
                // 로그아웃 관련 피터 설정
                .logout()
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                    .logoutSuccessUrl("/")
                .and()
                .build();
    }

    // SpringSecurity Filter가 필요없는 파일 Ignoring 작업
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());    // 정적 파일 ignoring
    }


    @Bean
    public UserDetailsService userDetailsService() {
        return username ->{
            User user = userService.findByUsername(username);
            if (user == null) {
                throw new UsernameNotFoundException(username);
            }
            return user;
        };
    }
}

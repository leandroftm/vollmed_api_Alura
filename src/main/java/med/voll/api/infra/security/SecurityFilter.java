package med.voll.api.infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import med.voll.api.domain.usuario.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UsuarioRepository repository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var tokenJWT = recuperarToken(request);
        //System.out.println("token " + tokenJWT);

        if(tokenJWT != null) {
            var subject = tokenService.getSubject(tokenJWT);
            //System.out.println("subject " + subject);
            var usuario = repository.findByLogin(subject);
            //System.out.println("usuario " + usuario);

            //força autenticação apenas se o usuario se logou previamente
            var authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        //necessário para chamar os próximos filtros na aplicação
        filterChain.doFilter(request, response);
    }

    private String recuperarToken(HttpServletRequest request) {
        var authorizationHeader = request.getHeader("Authorization");
        //System.out.println("authorization header " + authorizationHeader);
        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){

            //Os 2 returns fazem a mesma coisa de modos diferentes
            //return authorizationHeader.substring(7);

            return authorizationHeader.replace("Bearer ", "");
        }

       return null;
    }
}

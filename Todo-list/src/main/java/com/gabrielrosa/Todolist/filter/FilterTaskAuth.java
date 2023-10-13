package com.gabrielrosa.Todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.gabrielrosa.Todolist.user.IUserRepository;

import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter{

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

                //pegar autenticacao (usuario e senha)

                var authorization = request.getHeader("Authorization");
                var authEncoded = authorization.substring("Basic".length()).trim();

                byte[] authDecoded = Base64.getDecoder().decode(authEncoded);

                
                var authString = new String(authDecoded);
                
                System.out.println("Auth");
                System.out.println(authString);

                String[] credentials = authString.split(":");
                String username = credentials[0], password = credentials[1];



                //validar usuario

                var user = this.userRepository.findByUsername(username);

                if(user == null){
                    response.sendError(401);
                }else{
                    //valida senha

                    var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());

                    if(passwordVerify.verified) {
                        filterChain.doFilter(request, response);
                    }else{
                        response.sendError(401);
                    }

                }
                //validar senha
                //segue viagem
        
    }

    //implements Filter

    // @Override
    // public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
    //     throws IOException, ServletException {
            
    //         System.out.println("Chegou no filtro");
    //         chain.doFilter(request, response);
    // }


    
}

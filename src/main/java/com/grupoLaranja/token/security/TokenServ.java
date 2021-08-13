package com.grupoLaranja.token.security;

import com.grupoLaranja.token.model.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class TokenServ {

    @Value("${micro.jwt.expiration}") //Injetar propriedades do app properties
    private String expiration;

    @Value("${micro.jwt.secret}") //Injetar propriedades do app properties
    private String secret;

    public String gerarToken(Authentication authentication) {
        Usuario logado = (Usuario) authentication.getPrincipal(); // método para conseguir recuperar o usuário logado
        Date hoje = new Date();
        Date dataExpiracao = new Date(hoje.getTime() + Long.parseLong(expiration)); //somando a data de hoje mais a expiração
        return Jwts.builder()
                .setIssuer("Grupo Laranja") //Quem fez a geração do token
                .setSubject(logado.getId().toString())// método que define a qual usuário o token pertence
                .setIssuedAt(hoje)
                .setExpiration(dataExpiracao)
                .signWith(SignatureAlgorithm.HS256, secret).compact();
    }

    public boolean isTokenValido(String token) {
        try {
            Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Long getIdUsuario(String token) {
        Claims claims = Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token).getBody();
        return Long.parseLong(claims.getSubject());
    }

}

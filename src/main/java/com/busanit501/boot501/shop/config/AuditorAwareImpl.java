package com.busanit501.boot501.shop.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

@Log4j2
public class AuditorAwareImpl implements AuditorAware<String> {

    @Override
    public Optional<String> getCurrentAuditor() {
        log.info("getCurrentAuditor=============");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userId = "";
        if(authentication != null){
            userId = authentication.getName();
            log.info("getCurrentAuditor= userId============ " + userId);
        }
        return Optional.of(userId);
    }

}

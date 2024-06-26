package com.auth.mfa.service;

import com.auth.mfa.entity.UserEntity;
import com.auth.mfa.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService{

//    타 블로그 글을 보면 OAuth2UserService를 상속 받거나 직접 구현 하는 경우가 있는데
//    DefaultOAuth2UserService는 구현체이기에 이대로 진행 해도무관하다

    //DB 저장을 진행 하기 위해 유저 래퍼지토리 주입
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        //부모 클래스 loadUser로 부터 유저 정보를 가지고 오는 메서드 ( OAuth2 공급업체로 부터 사용자 정보를 가져오는 것 )
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println(oAuth2User.getAttributes());

        String registrationId = userRequest.getClientRegistration().getRegistrationId();


        OAuth2Response oAuth2Response = null;

        if (registrationId.equals("naver")) {

            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());

        } else if (registrationId.equals("google")) {
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());

        }else{
            return null;
        }

// 구글과 네이버 서비스마다 인증 규격이 상이하기 때문에 서로 다른 DTO로 담아야 한다.
// 따라서 OAuth2 DTO 객체 격인 OAuth2Response 객체를 인터페이스로 만든다.
// 네이버로 인터페이스를 구현, 구글 타입으로 인터페이스를 구현하는 식으로 진행한다.

        String username = oAuth2Response.getProvider()+ " "+oAuth2Response.getProviderId();

        UserEntity existData = userRepository.findByUsername(username);

        String role =null;

        if(existData ==null){

            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setRole(oAuth2Response.getEmail());
            userEntity.setEmail("ROLE_USER");

            userRepository.save(userEntity);

        }else{

            role = existData.getRole();
            existData.setEmail(oAuth2Response.getEmail());
            userRepository.save(existData);
        }

        return new CustomerOAuth2User(oAuth2Response, role);
    }
}


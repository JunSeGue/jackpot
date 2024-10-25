package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.config.error.ErrorCode;
import com.bitcamp.jackpot.config.error.exception.DatabaseException;
import com.bitcamp.jackpot.config.error.exception.DuplicateResourceException;
import com.bitcamp.jackpot.config.error.exception.InvalidPasswordException;
import com.bitcamp.jackpot.config.error.exception.MemberNotFoundException;
import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.dto.MemberDTO;
import com.bitcamp.jackpot.repository.HeartRepository;
import com.bitcamp.jackpot.repository.MemberRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;


import java.util.HashMap;
import java.util.Map;
import java.util.Optional;


@Service
@RequiredArgsConstructor
@Log4j2
public class MemberServiceImpl implements MemberService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final MemberRepository memberRepository;
    private final HeartRepository heartRepository;
    private final ModelMapper modelMapper;

    @Override
    public void signUp(MemberDTO memberDTO) {
        Member member = modelMapper.map(memberDTO, Member.class);
        member.encodePassword(memberDTO.getPwd(), bCryptPasswordEncoder);
        try {
            memberRepository.save(member);
        } catch (Exception e) {
            throw new DatabaseException();
        }
    }

    @Override
    public void edit(MemberDTO memberDTO) {
        try {
            Member member = memberRepository.findByEmail(memberDTO.getEmail())
                    .orElseThrow(MemberNotFoundException::new);

            member.updateMemberInfo(
                    memberDTO.getName(),
                    memberDTO.getPhone(),
                    memberDTO.getPwd(),
                    memberDTO.getAddress()
            );

            member.encodePassword(memberDTO.getPwd(), bCryptPasswordEncoder);
            memberRepository.save(member);
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }

    @Override
    public void remove(String email) {
        Member member = memberRepository.findByEmail(email).orElseThrow(MemberNotFoundException::new);
        heartRepository.deleteByMemberId(member);
        memberRepository.deleteByEmail(email);
    }


    @Override
    public MemberDTO findOne(String email) {
        Optional<Member> optionalMember = memberRepository.findByEmail(email);

        Member member = optionalMember.orElseThrow(() -> new EntityNotFoundException("Member not found"));
        return modelMapper.map(member, MemberDTO.class);

    }

    @NonNull
    @Override
    public Page<MemberDTO> findAll(int page, int size) {
        // 입력 값 검증
        if (page < 0 || size <= 0) {
            throw new IllegalArgumentException("Page index must be non-negative and size must be greater than 0.");
        }

        Pageable pageable = PageRequest.of(page, size);

        Page<Member> members = memberRepository.findAll(pageable);

        return members.map(member -> modelMapper.map(member, MemberDTO.class));
    }

    @Override
    public Map<String, Boolean> checkNickName(String nickName) {
        Map<String, Boolean> response = new HashMap<>();
        if (memberRepository.existsByNickName(nickName)) {
            response.put("isDuplicate", true);
            throw new DuplicateResourceException(true);
        } else {
            response.put("isDuplicate", false);
        }
        return response;
    }


    @Override
    public Map<String, Boolean> checkEmail(String email) {
        Map<String, Boolean> response = new HashMap<>();
        if (memberRepository.existsByEmail(email)) {
            response.put("isDuplicate", true);
            throw new DuplicateResourceException(true);
        } else {
            response.put("isDuplicate", false);
        }
        return response;
    }


    @Override
    public Map<String, Boolean> checkPwd(String email, String pwd) {
        // 이메일로 사용자 조회
        Member member = memberRepository.findByEmail(email)
                .orElseThrow(MemberNotFoundException::new);

        boolean isMatchedPwd = bCryptPasswordEncoder.matches(pwd, member.getPwd());
        if (!isMatchedPwd) {
            throw new InvalidPasswordException("알맞지 않은 비밀번호", ErrorCode.INVALID_INPUT_VALUE);
        }
        Map<String, Boolean> response = new HashMap<>();
        response.put("isMatchedPwd", true);
        return response;
    }


    @Override
    public boolean resetPwd(String email, String pwd) {

        Member member = memberRepository.findByEmail(email)
                .orElseThrow(MemberNotFoundException::new);
        try {
            member.changePassword(pwd, bCryptPasswordEncoder);
            memberRepository.save(member);
        } catch (Exception e) {
            throw new DatabaseException(ErrorCode.INVALID_INPUT_VALUE);
        }
        return true;
    }

    @Override
    public String findId(String name, String phone) {
        Optional<Member> result = memberRepository.findByNameAndPhone(name, phone);

        return result.map(Member::getEmail)
                .orElseThrow(MemberNotFoundException::new);
    }


    public void adminRemove(int memberId) {
        Member member = memberRepository.findById(memberId)
                .orElseThrow(() -> new MemberNotFoundException("해당 상품을 찾을 수 없습니다."));
        memberRepository.deleteById(memberId);
    }

    @Override
    public void adminEdit(int memberId, MemberDTO memberDTO) {
        Member member = memberRepository.findById(memberId)
                .orElseThrow(() -> new MemberNotFoundException("해당 상품을 찾을 수 없습니다."));
        modelMapper.map(memberDTO, member);
        memberRepository.save(member);
    }

    @Override
    public Page<MemberDTO> searchMembersByName(String name, Pageable pageable) {
        try {
            Page<Member> members = memberRepository.findByNameContaining(name, pageable);
            return members.map(member -> modelMapper.map(member, MemberDTO.class));
        } catch (Exception e) {
            throw new MemberNotFoundException("이름으로 회원을 검색하는 중 오류가 발생했습니다.");
        }
    }

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        if (memberRepository.findByEmail("jackpot@admin.com").isEmpty()){
            Member member = Member.builder()
                    .name("관리자")
                    .email("jackpot@admin.com")
                    .pwd("jackpot!ai8")
                    .phone("00000000000")
                    .nickName("관리자")
                    .address("관리자")
                    .grade(0)
                    .build();
            member.encodePassword(member.getPwd(), bCryptPasswordEncoder);
            memberRepository.save(member);
        }
    }

}
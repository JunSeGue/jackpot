package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.domain.*;
import com.bitcamp.jackpot.dto.*;
import com.bitcamp.jackpot.jwt.CustomUserDetails;
import com.bitcamp.jackpot.repository.DogRepository;
import com.bitcamp.jackpot.repository.FundRepository;
import com.bitcamp.jackpot.repository.HeartRepository;
import com.bitcamp.jackpot.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;


@Service
@Log4j2
@RequiredArgsConstructor
public class DogServiceImpl implements DogService {

    private final DogRepository dogRepository;
    private final HeartRepository heartRepository;
    private final MemberRepository memberRepository;
    private final FundRepository fundRepository;
    private final ModelMapper modelMapper;

//    private final String thumbnailOpt = "?type=u&w=333&h=139";
//    private final String mainImageOpt = "?type=f&w=630&h=450";
//    private final String detailImageOpt = "?type=f&w=225&h=150";

    private Boolean isSignInUser(){
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth.getClass() == UsernamePasswordAuthenticationToken.class;
    }

    private CustomUserDetails getUserDetails(){
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            return (CustomUserDetails) auth.getPrincipal();
    }

    @Override
    public DogDTO register(DogDTO dogDTO) {
        Dog dog = modelMapper.map(dogDTO, Dog.class);
        Dog savedDog = dogRepository.save(dog);

        return modelMapper.map(savedDog, DogDTO.class);
    }

    @Override
    public void remove(int dogId) {
        dogRepository.deleteById(dogId);
    }

    @Override
    public int edit(DogDTO dogDTO) {
        Optional<Dog> result = dogRepository.findById(dogDTO.getDogId());
        Dog dog = modelMapper.map(dogDTO, Dog.class);
        if (result.isEmpty()){
            //수정을 원하는 Dogd의 ID가 없는 경우 0을 리턴
            return 0;
        }else{
            return dogRepository.save(dog).getDogId();
        }
    }

    @Override
    public DogResponseDTO findOne(int dogId) {
        Optional<Dog> oDog = dogRepository.findById(dogId);
        Dog dog = oDog.orElseThrow();

        int isHeart= 0;

        if(isSignInUser()){
            CustomUserDetails ud = getUserDetails();
            Member member = memberRepository.findByEmail(ud.getUsername()).orElseThrow();
            Optional<Heart> oHeart = heartRepository.findByDogIdAndMemberId(dog,member);

            if(oHeart.isPresent()){
                isHeart = 1;
            }
        }

        List<Fund> funds = fundRepository.findFundByDogId(dogId, Pageable.unpaged());
        int totalCollection = 0;
        Set<Member> members = new HashSet<>();
        for (Fund fund : funds){
            totalCollection += fund.getCollection();
            members.add(fund.getMember());
        }

        return DogResponseDTO.builder()
                .dogId(dogId)
                .name(dog.getName())
                .species(dog.getSpecies())
                .age(dog.getAge())
                .gender(dog.getGender())
                .heart(dog.getHeart())
                .videoUrl(dog.getVideoUrl())
                .dogDetail(dog.getDogDetail())
                .regDate(dog.getRegDate())
                .fundCollection(totalCollection)
                .fundMemberNum(members.size())
                .isHeart(isHeart)
                .title(dog.getTitle())
                .mainImage(dog.getMainImage())
                .detailImage1(dog.getDetailImage1())
                .detailImage2(dog.getDetailImage2())
                .detailImage3(dog.getDetailImage3())
                .detailImage4(dog.getDetailImage4())
                .build();
    }

    @Override
    public Iterable<DogListDTO> dogList(DogListRequestDTO dogListRequestDTO) {
        int startIndex = (dogListRequestDTO.getSize() * (dogListRequestDTO.getPage() - 1)) + 1;
        int endIndex = dogListRequestDTO.getSize() * dogListRequestDTO.getPage();

        List<DogListDTO> response = new LinkedList<>();

        if (isSignInUser()) {
            //dog끌고와서 dogList 만들어서 페이지네이션에 맞게 리턴해주면됨.
            CustomUserDetails ud = getUserDetails();
            Member memberResult = memberRepository.findByEmail(ud.getUsername()).orElseThrow();

            List<Dog> heartDogs = dogRepository.findHeartDogByMemberId(memberResult, dogListRequestDTO.getPageable());
            int heartDogNum = dogRepository.findHeartDogByMemberId(memberResult,Pageable.unpaged()).size();

//            //하트독만 리턴하면 되는 경우
            if (heartDogs.size() >= dogListRequestDTO.getSize()) {
                response = dogsToDogListDTOs(heartDogs, true);
                //하트독도 리턴하고 논하트독도 리턴해야 하는 경우
            } else if (!heartDogs.isEmpty()) {
                response = dogsToDogListDTOs(heartDogs, true);
                DogListRequestDTO nextRequestDTO = DogListRequestDTO.builder()
                        .page(1)
                        .size(dogListRequestDTO.getSize())
                        .sort(dogListRequestDTO.getSort())
                        .build();
                List<Dog> notHeartDogs = dogRepository.findNotHeartDogByMemberId(memberResult, nextRequestDTO.getPageable());
                response.addAll(dogsToDogListDTOs(notHeartDogs, false));
                if (!response.isEmpty()) {
                    response = response.subList(0, Math.min(response.size(), dogListRequestDTO.getSize()));
                }
            } else {
                int noneHeartEndIndex = endIndex - heartDogNum;
                DogListRequestDTO nextRequestDTO = DogListRequestDTO.builder()
                        .page(noneHeartEndIndex / dogListRequestDTO.getSize())
                        .size(dogListRequestDTO.getSize())
                        .sort(dogListRequestDTO.getSort())
                        .build();
                List<Dog> notHeartDogs1 = dogRepository.findNotHeartDogByMemberId(memberResult, nextRequestDTO.getPageable());
                response = dogsToDogListDTOs(notHeartDogs1, false);
                nextRequestDTO.setPage(nextRequestDTO.getPage() + 1);
                List<Dog> notHeartDogs2 = dogRepository.findNotHeartDogByMemberId(memberResult, nextRequestDTO.getPageable());
                response.addAll(dogsToDogListDTOs(notHeartDogs2, false));
                int responseEndIndex = (noneHeartEndIndex % dogListRequestDTO.getSize()) + dogListRequestDTO.getSize()-1;
                int responseStartIndex = responseEndIndex - dogListRequestDTO.getSize() + 1;
                if (!response.isEmpty()) {
                    response = response.subList(Math.min(responseStartIndex, response.size() - 1), Math.min(responseEndIndex+ 1, response.size()));
                }
            }
            return response;
        }
        else{
            Page<Dog> dogsPage = dogRepository.findAll(dogListRequestDTO.getPageable());
            return dogsToDogListDTOs(dogsPage.getContent(),false);
        }
    }

    private List<DogListDTO> dogsToDogListDTOs(List<Dog> dogs, boolean isHeart) {
        List<DogListDTO> response = new LinkedList<>();
        dogs.forEach((dog)-> response.add(
                DogListDTO.builder()
                        .dogId(dog.getDogId())
                        .name(dog.getName())
                        .species(dog.getSpecies())
                        .heart(dog.getHeart())
                        .isHeart((isHeart)? 1:0)
                        .regDate(dog.getRegDate())
                        .thumbNail(dog.getMainImage())
                        .title(dog.getTitle())
                        .totalFund(fundRepository.findSumOfCollectionByDogId(dog.getDogId()).orElse(0))
                        .build()
        ));
        return response;
    }

    @Override
    public void addHeart(int dogId) {
        CustomUserDetails ud = getUserDetails();

        Optional<Member> oMember = memberRepository.findByEmail(ud.getUsername());
        Optional<Dog> oDog = dogRepository.findById(dogId);

        Optional<Heart> oHeart = heartRepository.findByDogIdAndMemberId(oDog.orElseThrow(), oMember.orElseThrow());
        if(oHeart.isEmpty()) {
            //dog의 heart갯수도 추가 해야됨.
            Dog dog = oDog.orElseThrow();
            DogDTO dogDTO = modelMapper.map(dog, DogDTO.class);
            dogDTO.setHeart(dog.getHeart() + 1);
            Dog editDog = modelMapper.map(dogDTO, Dog.class);
            dogRepository.save(editDog);

            Heart heart = Heart.builder()
                    .memberId(oMember.orElseThrow())
                    .dogId(dog)
                    .build();
            heartRepository.save(heart);
        }
        else {
            //dog의 heart갯수도 감소 해야됨.
            Dog dog = oDog.orElseThrow();
            DogDTO dogDTO = modelMapper.map(dog, DogDTO.class);
            dogDTO.setHeart(dog.getHeart() - 1);
            Dog editDog = modelMapper.map(dogDTO, Dog.class);
            dogRepository.save(editDog);

            heartRepository.delete(oHeart.get());
        }
    }

    @Override
    public void addFund(FundDTO fundDTO) {
        CustomUserDetails ud = getUserDetails();

        Optional<Member> oMember = memberRepository.findByEmail(ud.getUsername());
        Optional<Dog> oDog = dogRepository.findById(fundDTO.getDogId());

        Fund fund = Fund.builder()
                .dog(oDog.orElseThrow())
                .orderId(fundDTO.getOrderId())
                .member(oMember.orElseThrow())
                .collection(fundDTO.getCollection())
                .build();
        fundRepository.save(fund);
    }

    public Long getTotalDogNum(){
        return dogRepository.count();
    }

    public Map<String,Object> fundListMyPage() {
        // 현재 사용자의 memberId 가져오기
        CustomUserDetails ud = getUserDetails();
        Optional<Member> oMember = memberRepository.findByEmail(ud.getUsername());
        Member member = oMember.orElseThrow();
        int memberId = member.getMemberId();

        // memberId로 게시글 조회 (해당 멤버의 게시글만 조회)
        List<Fund> result = fundRepository.findAllByMemberId(memberId);

        // ModelMapper 설정
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.typeMap(Fund.class, FundDTO.class).addMappings(mapper -> {
            mapper.map(src -> src.getDog().getDogId(), FundDTO::setDogId);
            mapper.map(src -> src.getMember().getMemberId(), FundDTO::setMemberId);
        });

        List<FundDTO> dtoList = result.stream()
                .map(fund -> modelMapper.map(fund, FundDTO.class))
                .collect(Collectors.toList());

        List<DogResponseDTO> dogResponseList = result.stream()
                        .map(fund -> findOne(fund.getDog().getDogId())).collect(Collectors.toList());

        Map<String, Object> response = new HashMap<>();

        response.put("fundList", dtoList);
        response.put("dogResponseList", dogResponseList);

        return response;
    }

}

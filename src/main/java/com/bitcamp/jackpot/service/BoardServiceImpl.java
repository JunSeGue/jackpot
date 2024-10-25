package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.domain.Board;

import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.dto.*;
import com.bitcamp.jackpot.jwt.CustomUserDetails;
import com.bitcamp.jackpot.repository.BoardRepository;
import com.bitcamp.jackpot.repository.MemberRepository;
import com.bitcamp.jackpot.repository.ReplyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.CrossOrigin;


import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
@CrossOrigin(origins = "http://localhost:3000")
public class BoardServiceImpl implements BoardService {

    @Autowired
    private BoardRepository boardRepository;

    @Autowired
    private ReplyRepository replyRepository;

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private ModelMapper modelMapper;

    private CustomUserDetails getUserDetails() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return (CustomUserDetails) auth.getPrincipal();
    }

    @Override
    public void register(Board board) {

//        Board board = modelMapper.map(boardDTO, Board.class);
        //보드DTO를 컨트롤러로부터 매개변수로 받아서 모델매퍼이용해서 보드객체로 바꾸고

        int maxBoardId = boardRepository.findMaxBoardId();
        // 기존 포스트아이디를 알아오고 그 포스트아이디에 +1해서 셋포스트아이디 해줌. 알아오는 쿼리문은 레포지토리에 있음.

//        board.setBoardId(maxBoardId + 1);
        board.setBoardId(maxBoardId);
        //보드 객체에 글번호를 자동으로 1올려준다. 트리거 이용해도 되지만 그냥 단순한 방법 사용.

        CustomUserDetails ud = getUserDetails();
        // 토큰 오픈
        Optional<Member> oMember = memberRepository.findByEmail(ud.getUsername());
        // 이메일로 db에서 멤버객체를 찾아와서
        Member member = oMember.orElseThrow();
        // 옵셔널객체를 열어본다.
        board.setMember(member);
        // 열어서 나온 멤버 객체를 넣으면 자동으로 멤버id를 넣어줌...

        LocalDateTime now = LocalDateTime.now();
        board.setRegDate(now);
        //원래는 프론트에서 현재시간을 받아오게 되어있었지만 못받아와서 여기서 넣어줌

//        System.out.println(board);

        boardRepository.save(board);
        //보드레포지토리에 있는 쿼리문 이용해서 변경한 보드 객체를 저장함.
    }


    @Override
    public BoardDTO findOne(Integer boardId) {

        Optional<Board> result = boardRepository.findById(boardId);
        //옵셔널을 이용해서 널러블한 경우를 대비해 널-세이프하게 처리함. 글이 없는 경우도 안전하게 처리함.

        Board board = result.orElseThrow();
        //만약 글이 없는 경우, 조회된 게시물이 없으면 예외를 던짐

        BoardDTO boardDTO = modelMapper.map(board, BoardDTO.class);
//        BoardDTO boardDTO = entityToDto(board);
        //엔티티 인스턴스인 보드를 보드디티오로 변환해줌

        return boardDTO;
        // 보드디티오를 출력하기 위해 리턴해줌


        // 글번호와 글 타입을 받아와서 db에 검색하고 만약 있으면 그걸 객체로 만들어서 리턴하고
        // 만약 없으면 없다는 오류처리를 해야함.
    }

//    @Override
//    public PageResponseDTO<BoardDTO> findAll(PageRequestDTO pageRequestDTO) {
//        Pageable pageable = pageRequestDTO.getPageable("boardId");
//        // 페이지리퀘스트 객체로 읽어올 게시글 범위를 받아온다.
//
//        Page<Board> result = boardRepository.findAll(pageable);
//        // 범위만큼의 게시글들을 디비에서 가져와서 리절트 변수에 저장한다.
//
//        List<BoardDTO> boardDTOList = result.getContent().stream()
//                .map(board -> modelMapper.map(board, BoardDTO.class))
//                .collect(Collectors.toList());
//        // 리절트 변수에 저장된 보드 엔티티 객체들을 꺼내서 보드디티오 리스트로 변환한다.
//
//
//        PageResponseDTO<BoardDTO> response = new PageResponseDTO<BoardDTO>(pageRequestDTO, boardDTOList, (int)result.getTotalElements());
//
//        // 보드디티오 리스트를 페이지리스폰스로 바꾼다.
//
//        return response;
//    }



    @Override
    public PageResponseDTO<BoardDTO> findAll(PageRequestDTO pageRequestDTO) {
        // 전체 게시글을 가져온 후 필터링
        Pageable pageable = pageRequestDTO.getPageable("boardId");
        Page<Board> result = boardRepository.findAll(PageRequest.of(0, Integer.MAX_VALUE)); // 모든 게시글 조회

        List<BoardDTO> filteredBoardDTOList = result.getContent().stream()
                .map(board -> {
                    BoardDTO dto = modelMapper.map(board, BoardDTO.class);
                    dto.setMemberId(board.getMember() != null ? board.getMember().getMemberId() : null); // memberId 수동 설정
                    return dto;
                })
                .filter(dto -> dto.getType() == 1 || dto.getType() == 2) // type 필터링
                .collect(Collectors.toList());
        // 페이징 처리
        int totalElements = filteredBoardDTOList.size(); // 전체 요소 수
        int totalPages = (int) Math.ceil((double) totalElements / 10); // 전체 페이지 수
        int startIndex = Math.min(pageRequestDTO.getPage() * 10, totalElements);
        int endIndex = Math.min(startIndex + 10, totalElements);

        List<BoardDTO> paginatedList = filteredBoardDTOList.subList(startIndex, endIndex); // 페이지에 해당하는 요소만 서브리스트로 가져오기
//        log.info(paginatedList);
        // PageResponseDTO로 필터된 게시글 목록과 페이지 정보 반환
        return new PageResponseDTO<>(pageRequestDTO, paginatedList, totalPages - 1);
    }

    @Override
    public PageResponseDTO<BoardDTO> findAllAsk(PageRequestDTO pageRequestDTO) {
        // 전체 게시글을 가져온 후 필터링
        Pageable pageable = pageRequestDTO.getPageable("boardId");
        Page<Board> result = boardRepository.findAll(PageRequest.of(0, Integer.MAX_VALUE)); // 모든 게시글 조회

        List<BoardDTO> filteredBoardDTOList = result.getContent().stream()
                .map(board -> {
                    BoardDTO dto = modelMapper.map(board, BoardDTO.class);
                    dto.setMemberId(board.getMember() != null ? board.getMember().getMemberId() : null); // memberId 수동 설정
                    return dto;
                })
                .filter(dto -> dto.getType() == 1 || dto.getType() == 3) // type 필터링
                .collect(Collectors.toList());

        // 페이징 처리
        int totalElements = filteredBoardDTOList.size(); // 전체 요소 수
        int totalPages = (int) Math.ceil((double) totalElements / 10); // 전체 페이지 수
        int startIndex = Math.min(pageRequestDTO.getPage() * 10, totalElements);
        int endIndex = Math.min(startIndex + 10, totalElements);

        List<BoardDTO> paginatedList = filteredBoardDTOList.subList(startIndex, endIndex); // 페이지에 해당하는 요소만 서브리스트로 가져오기

        // PageResponseDTO로 필터된 게시글 목록과 페이지 정보 반환
        return new PageResponseDTO<>(pageRequestDTO, paginatedList, totalPages - 1);
    }

    @Override
    public List<BoardDTO> findAllAskMyPage(PageRequestDTO pageRequestDTO) {
        // 현재 사용자의 memberId 가져오기
        CustomUserDetails ud = getUserDetails();
        Optional<Member> oMember = memberRepository.findByEmail(ud.getUsername());
        Member member = oMember.orElseThrow();
        int memberId = member.getMemberId();
//        log.info("Current memberId: {}", memberId);

        // memberId로 게시글 조회 (해당 멤버의 게시글만 조회)
        Pageable pageable = pageRequestDTO.getPageable("boardId");
        Page<Board> result = boardRepository.findByMemberId(memberId, pageable);
//        log.info("Found boards: {}", result.getContent());

        // 조회된 게시글을 DTO로 변환하고 필터링
        List<BoardDTO> filteredBoardDTOList = result.getContent().stream()
                .map(board -> {
                    BoardDTO dto = modelMapper.map(board, BoardDTO.class);
                    dto.setMemberId(board.getMember() != null ? board.getMember().getMemberId() : null);
                    return dto;
                })
                .filter(dto -> {
                    boolean isType3 = dto.getType() == 3;
                    if (isType3) {
//                        log.info("Found type 3 board: {}", dto);
                    }
                    return isType3;
                })
                .collect(Collectors.toList());

        return filteredBoardDTOList;
    }

    @Override
    public BoardDTO edit(Integer id, Board board) {

        Optional<Board> result = boardRepository.findById(board.getBoardId());
        // 보드레포지토리를 통해 db에서 수정할 글을 찾아옴. 찾아온 글은 옵셔널(널에 안전)로 반환됨.

        Board boardToEdit = result.orElseThrow();
        // 옵셔널 객체가 비어있다면(= 찾아본 글이 없다면) 예외를 던지고 있으면 보드객체를 꺼내서 저장함.

        boardToEdit.edit(board.getTitle(), board.getContent());
        // 보드 엔티티의 스스로를 수정하는 에디트 메서드를 통해 제목과 내용을 수정함.

        CustomUserDetails ud = getUserDetails();
        // 토큰 오픈
        Optional<Member> oMember = memberRepository.findByEmail(ud.getUsername());
        // 이메일로 db에서 멤버객체를 찾아와서
        Member member = oMember.orElseThrow();
        // 옵셔널객체를 열어본다.
        boardToEdit.setMember(member);
        // 열어서 나온 멤버 객체를 넣으면 자동으로 멤버id를 넣어줌...

        LocalDateTime now = LocalDateTime.now();
        boardToEdit.setRegDate(now);
        //원래는 프론트에서 현재시간을 받아오게 되어있었지만 못받아와서 여기서 넣어줌

//        System.out.println(boardToEdit);

        boardRepository.save(boardToEdit);
        // 수정된 보드객체를 db에 저장함.

        BoardDTO boardEditted = modelMapper.map(board, BoardDTO.class);
        // 수정된 보드객체를 보드디티오 객체로 매핑함. 리턴하기 위해서.

        return boardEditted;
    }

//    @Override
//    public void remove(Integer boardId) {
//        log.info(boardId);
//        // 삭제하는 글의 글번호를 로그찍어본다.
//        boardRepository.deleteById(boardId);
//        // 단순히 삭제만 하는거라 복잡한 로직 필요 X, 오토박싱/언박싱 이뤄짐.
//    }

    @Override
    public void remove(Integer boardId) {
//        System.out.println(boardId);

        while (replyRepository.existsByBoardId(boardId)) {
            // 댓글이 있는지 반복해서 확인하면서 삭제
            replyRepository.deleteByBoardId(boardId);
            // 댓글을 모두 삭제하는 메서드 호출 (boardId 기준)
        }
        boardRepository.deleteById(boardId);
        // 댓글이 모두 삭제된 후 게시글 삭제
    }


//    @Override
//    public List<BoardDTO> search(String keyword) {
//        List<Board> boards = boardRepository.searchByTitle(keyword);
//        // 제목을 키워드로 검색해서 보즈 리스트에 저장함.
//        return boards.stream()
//                .map(board -> modelMapper.map(board, BoardDTO.class))
//                .collect(Collectors.toList());
//        // 보드 객체의 리스트를 보드디티오 객체의 리스트로 바꿔줌.
//    }

//    @Override
//    public PageResponseDTO<BoardDTO> search(String keyword, PageRequestDTO pageRequestDTO) {
//        // 검색어랑 페이지리퀘스트를 매개변수로 받아온다. 검색어로 검색하고 페이지리퀘스트로 리턴할 범위를 알려주는거지.
//
//        Pageable pageable = pageRequestDTO.getPageable("boardId");
//        // 보드아이디 순서대로 내림차순으로 정렬해서 페이저블 객체를 만든다.
//
//        Page<Board> result = boardRepository.findByTitleContainingIgnoreCase(keyword, pageable);
//        // 키워드로 제목검색 후 결과를 리절트에 저장
//
//        List<BoardDTO> boardDTOList = result.getContent().stream()
//                .map(board -> modelMapper.map(board, BoardDTO.class))
//                .collect(Collectors.toList());
//
//
//        return new PageResponseDTO<>(pageRequestDTO, boardDTOList, (int)result.getTotalElements());
//
//    }


    @Override
    public PageResponseDTO<BoardDTO> search(String keyword, PageRequestDTO pageRequestDTO) {
        Pageable pageable = pageRequestDTO.getPageable("boardId");

        Page<Board> result = boardRepository.findByTitleContainingIgnoreCase(keyword, pageable);

        List<BoardDTO> boardDTOList = result.getContent().stream()
                .map(board -> {
                    // BoardDTO로 변환
                    BoardDTO boardDTO = modelMapper.map(board, BoardDTO.class);
                    // Member 엔티티에서 memberId를 가져와서 설정
                    if (board.getMember() != null) {
                        boardDTO.setMemberId(board.getMember().getMemberId()); // Member 엔티티의 memberId 설정
                    }
                    return boardDTO;
                })
                .collect(Collectors.toList());

        return new PageResponseDTO<>(pageRequestDTO, boardDTOList, (int) result.getTotalElements());
    }


}

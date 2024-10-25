package com.bitcamp.jackpot;

import com.bitcamp.jackpot.domain.*;
import com.bitcamp.jackpot.dto.BoardDTO;
import com.bitcamp.jackpot.repository.BoardRepository;
import com.bitcamp.jackpot.repository.DogRepository;
import com.bitcamp.jackpot.repository.ReplyRepository;
import com.bitcamp.jackpot.repository.ShopRepository;
import com.bitcamp.jackpot.service.BoardService;
import com.bitcamp.jackpot.service.BoardServiceImpl;
import jakarta.persistence.*;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.LocalDateTime;
import java.util.Optional;

//@SpringBootTest
@Log4j2
class JackpotApplicationTests {
    //webhook테스트
//
//    @Autowired
//    private DogRepository dogRepository;
//
//    @Autowired
//    private BoardRepository boardRepository;
//
//    @Autowired
//    private ReplyRepository replyRepository;
//
//    @Autowired
//    private ShopRepository shopRepository;
//
//    @Test
//    void contextLoads() {
//    }
//
//    @Test
//    void registerShop() {
//
//        for (int i = 1; i < 50; i++) {
//            String testName = "testShopName" + i;
//            String testDetail = "testShopDetail" + i;
//            int testCategory = i % 4; // 카테고리를 0, 1, 2, 3으로 순환
//            int testPrice = i * 1000; // 가격은 1000 단위로 증가
//
//            Shop testShop = Shop.builder()
//                    .name(testName)
//                    .detail(testDetail)
//                    .category(testCategory)
//                    .price(testPrice)
//                    .build();
//
//            shopRepository.save(testShop);
//        }
//    }
//
//    @Test
//    void registerDog() {
//
//        for (int i = 1; i < 50; i++) {
//            String testName = "testName" + i;
//            int testAge = i;
//            String testSpecies = "testSpecies" + i;
//            int testHeart = i;
//            int testGender = i % 2;
//            String testDogDetail = "testDogDetail" + i;
//            String testVideoUrl = "testVideoUrl" + i;
//            Dog testDog = Dog.builder()
//                    .name(testName)
//                    .age(testAge)
//                    .species(testSpecies)
//                    .heart(testHeart)
//                    .gender(testGender)
//                    .dogDetail(testDogDetail)
//                    .videoUrl(testVideoUrl)
//                    .build();
//            dogRepository.save(testDog);
//        }
//    }
//
//    @Test
//    void testBoardRegister() {
//
////        Member member = Member.builder()
////                .memberId(1)
////                .build();
//
//        Board board = Board.builder()
//                .boardId(1)
////                .member(member)
//                .title("test title1")
//                .content("test content1")
//                .regDate(LocalDateTime.of(2024, 9, 26, 19, 0))
//                .type(2)
//                .build();
//        boardRepository.save(board);
//    }
//    // memberId = 1로 설정한 Member 객체가 실제로 DB에 존재하지 않아서 Board 엔티티가 저장안됨.
//    // memberId 넣는부분 주석처리 후 테스트하니 데이터 들어감. 테스트 성공.
//
//    @Test
//    void testBoardEdit() {
//        Integer boardId = 2;
//        // 수정해볼 게시글 글번호
//        Optional<Board> board = boardRepository.findById(boardId);
//        // 있는지없는지 모르니 옵셔널로. 보드아이디로 디비에 게시글 있는지 찾아봄.
//        Board board1 = board.orElseThrow();
//        // 오어엘스쓰로로 옵셔널 객체를 보드객체로 바꿔줌.
//        board1.edit("edited title", "edited content");
//        // 보드타입안에 수정메서드가 있음. 새로운 제목이랑 내용을 받음
//        boardRepository.save(board1);
//        // 변경내용 저장
//    }
//    // 테스트 성공
//
////    @Test
////    void testBoardEditSecond(){
////        Board board = new Board();
////        board.setBoardId(3);
////        board.setTitle("original title");
////        board.setContent("original content");
////        board.setRegDate(LocalDateTime.now());
////        board.setType(1);
////        // edit 메서드 호출
////        board.edit("edited title", "edited content");
////        // 수정된 내용을 리포지토리를 통해 저장
////        boardRepository.save(board);
////    }
//
//    @Test
//    void testBoardDelete() {
//        Integer boardId = 3;
////        Optional<Board> board = boardRepository.findById(boardId);
////        Board board1  = board.orElseThrow();
//        boardRepository.deleteById(boardId);
//    }
//    // 테스트 성공
//
////    @Test
////    void testBoardFindOne(){
////        BoardServiceImpl boardServiceImpl = new BoardServiceImpl();
////        BoardDTO boardDTO = BoardServiceImpl.findOne(1);
////        log.info(boardDTO);
////    }
//
//    @Test
//    void testReplyRegister() {
//        Reply reply = Reply.builder()
//                .replyId(1)
////                .member(member)
////                .boardId(2)
//                .content("test reply1")
//                .regDate(LocalDateTime.now())
//                .build();
//        replyRepository.save(reply);
//    }
//    // 테스트 성공
//
//    @Test
//    void testReplyDelete() {
//        Integer replyID = 1;
//        boardRepository.deleteById(replyID);
//    }
//    // 테스트 성공
//
//    @Test
//    void BoardDummyDataGenerateRegister() {
//
//        Member member = Member.builder()
//                .memberId(30) // 1번 멤버가 50개의 글을 작성함.
//                .build();
//
//        // 더미 데이터 생성
//        for (int i = 1; i <= 50; i++) {
//            Board board = Board.builder()
//                    .member(member)
//                    .title("test title" + i)
//                    .content("test content" + i)
//                    .regDate(LocalDateTime.now().minusDays(i))
//                    .type(i % 3 + 1)
//                    .build();
//
//            boardRepository.save(board);
//        }
//    }

}

package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.domain.Board;
import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.domain.Reply;
import com.bitcamp.jackpot.jwt.CustomUserDetails;
import com.bitcamp.jackpot.dto.ReplyDTO;
import com.bitcamp.jackpot.repository.BoardRepository;
import com.bitcamp.jackpot.repository.MemberRepository;
import com.bitcamp.jackpot.repository.ReplyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
public class ReplyServiceImpl implements ReplyService {

    @Autowired
    private final ReplyRepository replyRepository;

    @Autowired
    private final BoardRepository boardRepository;

    @Autowired
    private final MemberRepository memberRepository;

    @Autowired
    private final ModelMapper modelMapper;

    private CustomUserDetails getUserDetails(){
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return (CustomUserDetails) auth.getPrincipal();
    }

//    @Override
//    public void register(ReplyDTO replyDTO) {
//        Reply reply = modelMapper.map(replyDTO, Reply.class);
//        // 리플라이 엔티티객체로 디티오를 매핑함.
//
//        int maxReplyId = replyRepository.findMaxReplyId();
//        // 기존 리플라이아이디중 가장 최근 리플라이아이디를 알아옴. 가장 큰 숫자.
//
//        reply.setReplyId(maxReplyId + 1);
//        // 리플라이객체의 글번호를 자동으로 1올려준다.
//
//        CustomUserDetails ud = getUserDetails();
//        // 토큰 오픈
//        Optional<Member> oMember = memberRepository.findByEmail(ud.getUsername());
//        // 이메일로 db에서 멤버객체를 찾아와서
//        Member member = oMember.orElseThrow();
//        // 옵셔널객체를 열어본다.
//        reply.setMember(member);
//        // 열어서 나온 멤버 객체를 넣으면 자동으로 멤버id를 넣어줌...
//
//        System.out.println(reply);
//
//        replyRepository.save(reply);
//        // 매핑후에 작성된 댓글을 저장함.
//    }

    @Override
    public void register(ReplyDTO replyDTO) {
        Reply reply = modelMapper.map(replyDTO, Reply.class);

        Optional<Board> optionalBoard = boardRepository.findById(replyDTO.getBoardId());
        Board board = optionalBoard.orElseThrow(() -> new RuntimeException(""));

        reply.setBoard(board);

        int maxReplyId = replyRepository.findMaxReplyId();
        reply.setReplyId(maxReplyId + 1);

        CustomUserDetails ud = getUserDetails();
        Optional<Member> oMember = memberRepository.findByEmail(ud.getUsername());
        Member member = oMember.orElseThrow();
        reply.setMember(member);

        System.out.println(reply);

        replyRepository.save(reply);
    }


//    @Override
//    public ReplyDTO edit(Integer replyId, ReplyDTO replyDTO) {
//        Optional<Reply> reply = replyRepository.findById(replyId);
//        // 기존 댓글을 찾아서 리플라이 엔티티로 가져옴
//
//        if (reply.isPresent()) {
//            // 만약 옵셔널 객체 안에 리플라이아이디로 찾은 댓글이 있으면
//            Reply isReply = reply.orElseThrow();
//            // 옵셔널객체를 까서 리플라이 엔티티객체로 만들고
//            isReply = modelMapper.map(replyDTO, Reply.class);
//            // 까놓은 리플라이엔티티를 새롭게 수정한걸로 대체해버림
//            replyRepository.save(isReply);
//            // 그리고나서 새롭게 대체해버린걸 저장해버림.
//            return modelMapper.map(isReply, ReplyDTO.class);
//            // 저장한 리플라이 객체를 리플라이디티오로 매핑해서 리턴함.
//        } else {
//            throw new RuntimeException("댓글을 찾을 수 없습니다.");
//        }
//    }

    @Override
    public ReplyDTO edit(Integer replyId, ReplyDTO replyDTO) {
        Optional<Reply> optionalReply = replyRepository.findById(replyId);

        // 기존 댓글을 찾으면
        if (optionalReply.isPresent()) {
            Reply existingReply = optionalReply.get(); // 기존 댓글 가져오기

            // 기존 댓글의 내용을 수정
            existingReply.setContent(replyDTO.getContent());
            // 다른 필요한 필드도 여기에 설정할 수 있음 (예: 수정 날짜 등)

            // 변경된 내용을 저장
            replyRepository.save(existingReply);

            // 수정된 댓글을 ReplyDTO로 변환하여 반환
            return modelMapper.map(existingReply, ReplyDTO.class);
        } else {
            throw new RuntimeException("댓글을 찾을 수 없습니다.");
        }
    }


    @Override
    public void remove(Integer replyId) {
        replyRepository.deleteById(replyId);
        // 레포지토리 이용해서 단순삭제
    }

//    @Override
//    public List<ReplyDTO> findAll(Integer boardId) {
//        return List.of();
//    }

//        @Override
//        public List<ReplyDTO> findAll(Integer boardId) {
//            List<Reply> replies = replyRepository.findAllByBoardId(boardId);
//            log.info(replies);
//
//            return replies.stream()
//                    .map(reply -> modelMapper.map(reply, ReplyDTO.class))
//                    .collect(Collectors.toList());
//        }
@Override
public List<ReplyDTO> findAll(Integer boardId) {
    // boardId에 해당하는 모든 Reply 엔티티 조회
    List<Reply> replies = replyRepository.findAllByBoardId(boardId);
//    log.info("Replies: " + replies);

    // Reply 엔티티를 ReplyDTO로 변환하고 memberId 추가
    return replies.stream()
            .map(reply -> {
                // Reply 엔티티를 ReplyDTO로 변환
                ReplyDTO replyDTO = modelMapper.map(reply, ReplyDTO.class);

                // Reply에서 Member 엔티티의 memberId를 ReplyDTO에 설정
                replyDTO.setMemberId(reply.getMember().getMemberId());

                return replyDTO;
            })
            .collect(Collectors.toList());
}


    //+ register(ReplyDTO replyDTO): ReplyDTO

    //+ edit(int id, ReplyDTO replyDTO): ReplyDTO

    //+ remove(Int Id): void

    //+ findAll: List<ReplyDTO>


}

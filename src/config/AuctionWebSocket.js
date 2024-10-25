import React, {useEffect} from 'react';
import io from 'socket.io-client';  // socket.io-client import

// const socket = io('http://223.130.158.97/socket.io/',
//     {
//         transports: ['websocket'],  // WebSocket으로만 연결 시도
//         upgrade: false, // Long Polling으로 업그레이드 방지
//         query: {
//             path: window.location.pathname // 현재 경로를 서버에 전송
//         }
//     }
// );  // Node.js WebSocket 서버에 연결

const socket = io({
    path: "/socket.io/"
});

const AuctionWebSocket = ({
                              onBidUpdate,
                              onTimerUpdate,
                              onAuctionUpdate,
                              onAuctionEnd,
                              onLastBidder,
                              onAuctionStart
                          }) => {
    const handleTimerUpdate = (timeLeft) => {
        console.log(timeLeft);
        if (typeof onTimerUpdate === 'function') {
            onTimerUpdate(timeLeft);  // 타이머 업데이트 함수 호출
        } else {
            console.error('onTimerUpdate is not a function');
        }
    };
    useEffect(() => {
        socket.on('auction start', (data) => {
            console.log('Received auction start event:', data);
            if (typeof onAuctionStart === 'function') {
                onAuctionStart(data);  // 부모 컴포넌트에 경매 시작 처리
            }
        });

        socket.on('auction update', (data) => {
            console.log('소켓에서 받은 경매 시작 데이터', data);
            onAuctionUpdate(data);
        })

        // WebSocket으로 타이머 업데이트 받기
        socket.on('timer update', handleTimerUpdate);

        // WebSocket으로 경매 종료 이벤트 받기
        socket.on('auction ended', (data) => {
            console.log('Received auction ended event:', data);
            onAuctionEnd(data);  // 부모 컴포넌트에 경매 종료 처리
        });

        socket.on('bid update', (bidData) => {
            console.log('Received bid update:', bidData);
            onBidUpdate(bidData);  // 부모 컴포넌트에 입찰 데이터 전달
        });

        socket.on('last bidder', (data) => {
            console.log("낙찰자 정보 수신:", data);
            const {winner} = data;
            // 부모 컴포넌트로 최종 낙찰자 정보 전달
            if (typeof onLastBidder === 'function') {
                onLastBidder(winner);
            }
            // 모든 사용자에게 알림

        });
        // 컴포넌트 언마운트 시 WebSocket 연결 해제
        return () => {
            socket.off('timer update', handleTimerUpdate);
            socket.off('auction update');  // 경매 업데이트 해제
            socket.off('bid update');  // 입찰 업데이트 해제
            socket.off('auction ended');  // 경매 종료 이벤트 해제
            socket.off('last bidder');  // 경매 종료 이벤트 해제
            socket.off('auction start');  // 경매 종료 이벤트 해제
            // socket.disconnect();  // 소켓 연결 해제
        };
    }, [onBidUpdate, onTimerUpdate, onAuctionUpdate, onAuctionEnd, onLastBidder, onAuctionStart]);

    return null;  // 이 컴포넌트는 UI를 렌더링하지 않음
};

export default AuctionWebSocket;

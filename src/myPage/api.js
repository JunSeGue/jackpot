import apiClient, { apiNoToken } from "../token/AxiosConfig";
import { logout } from "../token/Logout";

export const deleteUser = async () => {
  try {
    const response = await apiClient.delete(`member/remove`);
    console.log(response.status);
    if (response.status === 204) {
      alert("회원탈퇴에 성공했습니다.");
      logout();
    }
  } catch (error) {
    console.error("Error deleting member:", error);
    alert("회원탈퇴에 실패했습니다. 다시 시도해주세요.");
  }
};

export const checkNickName = async (nickname) => {
  console.log(nickname);
  try {
    const response = await apiNoToken.get(`member/checkNickName`, {
      params: { nickName: nickname },
    });
    console.log(response);

    if (response) {
      alert("사용 가능한 닉네임입니다.");
    } else {
      alert("닉네임이 이미 사용 중입니다.");
    }
  } catch (error) {
    console.log(error);
    alert("닉네임 중복 확인 중 오류가 발생했습니다.");
  }
};

export const editUser = async (memberDTO) => {
  console.log(memberDTO);
  try {
    const response = await apiClient.put("member/edit", memberDTO);
    if (response.status === 200) {
      alert("회원정보 수정에 성공했습니다.");
      // 수정된 정보로 상태 업데이트
    }
  } catch (error) {
    console.error("Error updating member:", error);
    alert("회원정보 수정에 실패했습니다. 다시 시도해주세요.");
  }
};

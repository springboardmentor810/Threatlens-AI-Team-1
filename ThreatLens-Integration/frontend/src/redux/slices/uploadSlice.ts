import { createAsyncThunk, createSlice, PayloadAction } from "@reduxjs/toolkit";
import { uploadApi } from "@/api/uploadApi";
import { UploadedFile } from "@/types/upload.types";

interface UploadState {
  history: UploadedFile[];
  activeUploads: UploadedFile[];
  status: "idle" | "loading" | "failed";
}

const initialState: UploadState = {
  history: [],
  activeUploads: [],
  status: "idle",
};

export const fetchUploadHistory = createAsyncThunk("upload/fetchHistory", async () => {
  return uploadApi.getHistory();
});

const uploadSlice = createSlice({
  name: "upload",
  initialState,
  reducers: {
    addActiveUpload(state, action: PayloadAction<UploadedFile>) {
      state.activeUploads.unshift(action.payload);
    },
    updateActiveUploadProgress(
      state,
      action: PayloadAction<{ id: string; progress: number; status?: UploadedFile["status"] }>
    ) {
      const file = state.activeUploads.find((f) => f.id === action.payload.id);
      if (file) {
        file.progress = action.payload.progress;
        if (action.payload.status) file.status = action.payload.status;
      }
    },
    /**
     * `draftId` is the local placeholder used while the upload is in flight;
     * `file` is the server's record, whose id is the detection id. They differ,
     * which is why the draft cannot simply be matched on file.id - doing that
     * left the finished upload stuck in the active list and made the history
     * entry unlinkable.
     */
    completeUpload(
      state,
      action: PayloadAction<{ draftId: string; file: UploadedFile }>
    ) {
      state.activeUploads = state.activeUploads.filter(
        (f) => f.id !== action.payload.draftId
      );
      state.history.unshift(action.payload.file);
    },
  },
  extraReducers: (builder) => {
    builder.addCase(fetchUploadHistory.fulfilled, (state, action) => {
      state.history = action.payload;
    });
  },
});

export const { addActiveUpload, updateActiveUploadProgress, completeUpload } = uploadSlice.actions;
export default uploadSlice.reducer;

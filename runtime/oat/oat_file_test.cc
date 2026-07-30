/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "oat_file.h"

#include <dlfcn.h>
#include <fcntl.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>

#include "android-base/scopeguard.h"
#include "android-base/unique_fd.h"
#include "base/array_ref.h"
#include "base/file_utils.h"
#include "base/globals.h"
#include "base/mem_map.h"
#include "base/mman.h"
#include "base/os.h"
#include "common_runtime_test.h"
#include "dexopt_test.h"
#include "elf_file.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "oat.h"
#include "scoped_thread_state_change-inl.h"
#include "vdex_file.h"

namespace art HIDDEN {

using ::testing::HasSubstr;

using std::string_view_literals::operator""sv;

// Returns the offset of the first dex file in the vdex file.
static void GetFirstDexFileOffset(const std::string& vdex_filename, /*out*/ size_t* offset) {
  std::string error_msg;
  std::unique_ptr<VdexFile> vdex_file =
      VdexFile::Open(vdex_filename, /*low_4gb=*/false, &error_msg);
  ASSERT_NE(vdex_file, nullptr) << error_msg;
  const uint8_t* ptr = vdex_file->GetNextDexFileData(/*cursor=*/nullptr, /*dex_file_index=*/0);
  ASSERT_NE(ptr, nullptr) << "No dex code in vdex";
  ASSERT_GE(ptr, vdex_file->Begin());
  ASSERT_LT(ptr, vdex_file->End());
  *offset = ptr - vdex_file->Begin();
}

static ::testing::AssertionResult DladdrIdentifies(const uint8_t* address,
                                                   const char* expected_symbol) {
  Dl_info info = {};
  if (dladdr(address, &info) == 0) {
    return ::testing::AssertionFailure()
           << "dladdr did not identify address " << static_cast<const void*>(address);
  }
  if (info.dli_sname == nullptr || strcmp(info.dli_sname, expected_symbol) != 0) {
    return ::testing::AssertionFailure()
           << "dladdr identified symbol '"
           << (info.dli_sname != nullptr ? info.dli_sname : "<null>") << "' at " << info.dli_saddr
           << ", expected '" << expected_symbol << "' at " << static_cast<const void*>(address);
  }
  if (static_cast<const void*>(info.dli_saddr) != static_cast<const void*>(address)) {
    return ::testing::AssertionFailure()
           << "dladdr identified '" << expected_symbol << "' at " << info.dli_saddr
           << ", expected exact address " << static_cast<const void*>(address);
  }
  return ::testing::AssertionSuccess();
}

class OatFileTest : public DexoptTest {};

TEST_F(OatFileTest, LoadOat) {
  std::string dex_location = GetScratchDir() + "/LoadOat.jar";

  Copy(GetDexSrc1(), dex_location);
  GenerateOatForTest(dex_location.c_str(), CompilerFilter::kSpeed);

  std::string oat_location;
  std::string error_msg;
  ASSERT_TRUE(OatFileAssistant::DexLocationToOatFilename(
      dex_location, kRuntimeISA, &oat_location, &error_msg))
      << error_msg;
  std::unique_ptr<OatFile> odex_file(OatFile::Open(/*zip_fd=*/-1,
                                                   oat_location,
                                                   oat_location,
                                                   /*executable=*/false,
                                                   /*low_4gb=*/false,
                                                   dex_location,
                                                   &error_msg));
  ASSERT_TRUE(odex_file.get() != nullptr);

  // Check that the vdex file was loaded in the reserved space of odex file.
  EXPECT_EQ(odex_file->GetVdexFile()->Begin(), odex_file->VdexBegin());

  // Non-executable path loads reject DlOpenOatFile and use ElfOatFile. The
  // private mapping must not appear in the platform linker's module list.
  Dl_info info = {};
  EXPECT_EQ(dladdr(odex_file->Begin(), &info), 0);
}

TEST_F(OatFileTest, LoadAtReservation) {
  std::string dex_location = GetScratchDir() + "/LoadAtReservation.jar";
  Copy(GetDexSrc1(), dex_location);
  GenerateOatForTest(dex_location.c_str(), CompilerFilter::kSpeed);

  std::string oat_location;
  std::string error_msg;
  ASSERT_TRUE(OatFileAssistant::DexLocationToOatFilename(
      dex_location, kRuntimeISA, &oat_location, &error_msg))
      << error_msg;

  std::unique_ptr<File> oat_file(OS::OpenFileForReading(oat_location.c_str()));
  ASSERT_NE(oat_file, nullptr);
  std::unique_ptr<ElfFile> elf_file(ElfFile::Open(oat_file.get(), /*low_4gb=*/false, &error_msg));
  ASSERT_NE(elf_file, nullptr) << error_msg;
  size_t loaded_size;
  ASSERT_TRUE(elf_file->GetLoadedSize(&loaded_size, &error_msg)) << error_msg;

  MemMap reservation = MemMap::MapAnonymousAligned("OatFileTest reservation",
                                                   loaded_size,
                                                   PROT_NONE,
                                                   /*low_4gb=*/false,
                                                   kElfSegmentAlignment,
                                                   &error_msg);
  ASSERT_TRUE(reservation.IsValid()) << error_msg;
  const uint8_t* expected_elf_begin = reservation.Begin();

  std::unique_ptr<OatFile> loaded(OatFile::Open(/*zip_fd=*/-1,
                                                oat_location,
                                                oat_location,
                                                /*executable=*/true,
                                                /*low_4gb=*/false,
                                                ArrayRef<const std::string>(&dex_location, 1u),
                                                /*dex_files=*/{},
                                                &reservation,
                                                &error_msg));
  ASSERT_NE(loaded, nullptr) << error_msg;
  EXPECT_FALSE(reservation.IsValid());
  EXPECT_EQ(loaded->ComputeElfBegin(&error_msg), expected_elf_begin) << error_msg;
  EXPECT_EQ(loaded->GetVdexFile()->Begin(), loaded->VdexBegin());
}

TEST_F(OatFileTest, FileDescriptorLoadUsesElfOatFile) {
  std::string dex_location = GetScratchDir() + "/FileDescriptorLoad.jar";
  std::string oat_location = GetScratchDir() + "/FileDescriptorLoad.odex";
  std::string vdex_location = GetVdexFilename(oat_location);
  Copy(GetDexSrc1(), dex_location);
  ASSERT_NO_FATAL_FAILURE(GenerateOdexForTest(dex_location, oat_location, CompilerFilter::kSpeed));

  android::base::unique_fd zip_fd(open(dex_location.c_str(), O_RDONLY | O_CLOEXEC));
  android::base::unique_fd vdex_fd(open(vdex_location.c_str(), O_RDONLY | O_CLOEXEC));
  android::base::unique_fd oat_fd(open(oat_location.c_str(), O_RDONLY | O_CLOEXEC));
  ASSERT_TRUE(zip_fd.ok());
  ASSERT_TRUE(vdex_fd.ok());
  ASSERT_TRUE(oat_fd.ok());

  std::string error_msg;
  std::unique_ptr<OatFile> loaded(OatFile::Open(zip_fd.get(),
                                                vdex_fd.get(),
                                                oat_fd.get(),
                                                oat_location,
                                                /*executable=*/true,
                                                /*low_4gb=*/false,
                                                ArrayRef<const std::string>(&dex_location, 1u),
                                                /*dex_files=*/{},
                                                /*reservation=*/nullptr,
                                                &error_msg));
  ASSERT_NE(loaded, nullptr) << error_msg;
  EXPECT_TRUE(error_msg.empty()) << error_msg;
  EXPECT_EQ(loaded->GetVdexFile()->Begin(), loaded->VdexBegin());

  // The fd overload selects ElfOatFile directly, even for executable input.
  Dl_info info = {};
  EXPECT_EQ(dladdr(loaded->Begin(), &info), 0);
}

TEST_F(OatFileTest, DuplicateLoadsHaveIndependentState) {
  std::string dex_location = GetScratchDir() + "/DuplicateLoads.jar";
  Copy(GetDexSrc1(), dex_location);
  GenerateOatForTest(dex_location.c_str(), CompilerFilter::kSpeed);

  std::string oat_location;
  std::string error_msg;
  ASSERT_TRUE(OatFileAssistant::DexLocationToOatFilename(
      dex_location, kRuntimeISA, &oat_location, &error_msg))
      << error_msg;

  auto open = [&]() {
    error_msg.clear();
    return std::unique_ptr<OatFile>(OatFile::Open(/*zip_fd=*/-1,
                                                  oat_location,
                                                  oat_location,
                                                  /*executable=*/true,
                                                  /*low_4gb=*/false,
                                                  dex_location,
                                                  &error_msg));
  };
  std::unique_ptr<OatFile> first = open();
  ASSERT_NE(first, nullptr) << error_msg;
  std::unique_ptr<OatFile> second = open();
  ASSERT_NE(second, nullptr) << error_msg;

  std::string first_error;
  std::string second_error;
  EXPECT_NE(first->ComputeElfBegin(&first_error), second->ComputeElfBegin(&second_error));
  EXPECT_TRUE(first_error.empty()) << first_error;
  EXPECT_TRUE(second_error.empty()) << second_error;
  EXPECT_NE(first->Begin(), second->Begin());
  if (first->BssBegin() != nullptr || second->BssBegin() != nullptr) {
    ASSERT_NE(first->BssBegin(), nullptr);
    ASSERT_NE(second->BssBegin(), nullptr);
    EXPECT_NE(first->BssBegin(), second->BssBegin());
  }
  if (first->VdexBegin() != nullptr || second->VdexBegin() != nullptr) {
    ASSERT_NE(first->VdexBegin(), nullptr);
    ASSERT_NE(second->VdexBegin(), nullptr);
    EXPECT_NE(first->VdexBegin(), second->VdexBegin());
  }

  second.reset();
  EXPECT_TRUE(first->GetOatHeader().IsValid());
  EXPECT_EQ(first->GetVdexFile()->Begin(), first->VdexBegin());
}

TEST_F(OatFileTest, SdmZipEntryLoad) {
  std::string dex_location = GetScratchDir() + "/SdmZipEntryLoad.jar";
  std::string sdm_location =
      GetScratchDir() + "/SdmZipEntryLoad." + GetInstructionSetString(kRuntimeISA) + ".sdm";
  std::string dm_location = GetScratchDir() + "/SdmZipEntryLoad.dm";
  std::string sdc_location = GetScratchDir() + "/SdmZipEntryLoad.sdc";
  Copy(GetMultiDexUncompressedAlignedSrc1(), dex_location);

  ASSERT_NO_FATAL_FAILURE(GenerateSdmDmForTest(dex_location,
                                               sdm_location,
                                               dm_location,
                                               CompilerFilter::kSpeedProfile,
                                               /*include_app_image=*/false,
                                               /*compilation_reason=*/"cloud"));
  ASSERT_NO_FATAL_FAILURE(
      CreateSecureDexMetadataCompanion(sdm_location, runtime_->GetApexVersions(), sdc_location));

  std::string error_msg;
  std::unique_ptr<OatFile> loaded(OatFile::OpenFromSdm(sdm_location,
                                                       sdc_location,
                                                       dm_location,
                                                       dex_location,
                                                       /*executable=*/true,
                                                       &error_msg));
  ASSERT_NE(loaded, nullptr) << error_msg;
  EXPECT_EQ(loaded->GetVdexFile()->Begin(), loaded->VdexBegin());

  Dl_info info = {};
  if (kIsTargetAndroid) {
    ASSERT_NE(dladdr(loaded->Begin(), &info), 0);
    EXPECT_STREQ(info.dli_sname, "oatdata");
    EXPECT_THAT(info.dli_fname, HasSubstr("!/primary.odex"));
  } else {
    // Desktop dlopen does not implement Bionic's ZIP-entry extension, so the
    // Linux host path falls back to ElfOatFile.
    EXPECT_EQ(dladdr(loaded->Begin(), &info), 0);
  }
}

TEST_F(OatFileTest, ChangingMultiDexUncompressed) {
  std::string dex_location = GetScratchDir() + "/MultiDexUncompressedAligned.jar";

  Copy(GetTestDexFileName("MultiDexUncompressedAligned"), dex_location);
  GenerateOatForTest(dex_location.c_str(), CompilerFilter::kVerify);

  std::string oat_location;
  std::string error_msg;
  ASSERT_TRUE(OatFileAssistant::DexLocationToOatFilename(
      dex_location, kRuntimeISA, &oat_location, &error_msg))
      << error_msg;

  // Ensure we can load that file. Just a precondition.
  {
    std::unique_ptr<OatFile> odex_file(OatFile::Open(/*zip_fd=*/-1,
                                                     oat_location,
                                                     oat_location,
                                                     /*executable=*/false,
                                                     /*low_4gb=*/false,
                                                     dex_location,
                                                     &error_msg));
    ASSERT_TRUE(odex_file != nullptr);
    ASSERT_EQ(2u, odex_file->GetOatDexFiles().size());
  }

  // Now replace the source.
  Copy(GetTestDexFileName("MainUncompressedAligned"), dex_location);

  // And try to load again.
  std::unique_ptr<OatFile> odex_file(OatFile::Open(/*zip_fd=*/-1,
                                                   oat_location,
                                                   oat_location,
                                                   /*executable=*/false,
                                                   /*low_4gb=*/false,
                                                   dex_location,
                                                   &error_msg));
  EXPECT_TRUE(odex_file == nullptr);
  EXPECT_NE(std::string::npos, error_msg.find("expected 2 uncompressed dex files, but found 1"))
      << error_msg;
}

TEST_F(OatFileTest, DlOpenLoad) {
  std::string dex_location = GetScratchDir() + "/LoadOat.jar";

  Copy(GetDexSrc1(), dex_location);
  GenerateOatForTest(dex_location.c_str(), CompilerFilter::kSpeed);

  std::string oat_location;
  std::string error_msg;
  ASSERT_TRUE(OatFileAssistant::DexLocationToOatFilename(
      dex_location, kRuntimeISA, &oat_location, &error_msg))
      << error_msg;

  // Clear previous errors if any.
  dlerror();
  error_msg.clear();
  std::unique_ptr<OatFile> odex_file(OatFile::Open(/*zip_fd=*/-1,
                                                   oat_location,
                                                   oat_location,
                                                   /*executable=*/true,
                                                   /*low_4gb=*/false,
                                                   dex_location,
                                                   &error_msg));
  ASSERT_NE(odex_file.get(), nullptr) << error_msg;

#ifdef __GLIBC__
  if (!error_msg.empty()) {
    // If a valid oat file was returned but there was an error message, then dlopen failed
    // but the backup ART ELF loader successfully loaded the oat file.
    // There are a few expected reasons for this:
    //   - a bug in glibc that prevents loading dynamic shared objects with a read-only dynamic
    //     section https://sourceware.org/bugzilla/show_bug.cgi?id=28340.
    //   - glibc >= 2.41 fails to dlopen shared objects that don't have GNU_STACK segment,
    //     see https://lists.gnu.org/archive/html/info-gnu/2025-01/msg00014.html
    ASSERT_TRUE(
        error_msg == "DlOpen does not support read-only .dynamic section." ||
        error_msg ==
            "Failed to dlopen '" + oat_location + "': " + oat_location +
                ": cannot enable executable stack as shared object requires: Invalid argument")
        << error_msg;
    GTEST_SKIP() << error_msg;
  }
#else
  // If a valid oat file was returned with no error message, then dlopen was successful.
  ASSERT_TRUE(error_msg.empty()) << error_msg;
#endif

  const char* dlerror_msg = dlerror();
  ASSERT_EQ(dlerror_msg, nullptr) << dlerror_msg;

  // Ensure that the oat file is loaded with dlopen by requesting information about it
  // using dladdr.
  Dl_info info;
  ASSERT_NE(dladdr(odex_file->Begin(), &info), 0);
  EXPECT_STREQ(info.dli_fname, oat_location.c_str())
      << "dli_fname: " << info.dli_fname << ", location: " << oat_location;
  EXPECT_STREQ(info.dli_sname, "oatdata") << info.dli_sname;

  EXPECT_TRUE(DladdrIdentifies(odex_file->Begin(), "oatdata"));
  EXPECT_TRUE(DladdrIdentifies(odex_file->Begin() + odex_file->GetOatHeader().GetExecutableOffset(),
                               "oatexec"));
  EXPECT_TRUE(DladdrIdentifies(odex_file->End() - sizeof(uint32_t), "oatlastword"));
  if (odex_file->DataImgRelRoBegin() != nullptr) {
    EXPECT_TRUE(DladdrIdentifies(odex_file->DataImgRelRoBegin(), "oatdataimgrelro"));
    EXPECT_TRUE(DladdrIdentifies(odex_file->DataImgRelRoEnd() - sizeof(uint32_t),
                                 "oatdataimgrelrolastword"));
    if (odex_file->DataImgRelRoAppImage() != odex_file->DataImgRelRoEnd()) {
      EXPECT_TRUE(DladdrIdentifies(odex_file->DataImgRelRoAppImage(), "oatdataimgrelroappimage"));
    }
  }
  if (odex_file->BssBegin() != nullptr) {
    EXPECT_TRUE(DladdrIdentifies(odex_file->BssBegin(), "oatbss"));
    EXPECT_TRUE(DladdrIdentifies(odex_file->BssEnd() - sizeof(uint32_t), "oatbsslastword"));
    if (odex_file->BssMethodsOffset() < odex_file->BssRootsOffset()) {
      EXPECT_TRUE(
          DladdrIdentifies(odex_file->BssBegin() + odex_file->BssMethodsOffset(), "oatbssmethods"));
    }
    if (odex_file->BssRootsOffset() < odex_file->BssSize()) {
      EXPECT_TRUE(
          DladdrIdentifies(odex_file->BssBegin() + odex_file->BssRootsOffset(), "oatbssroots"));
    }
  }
  if (odex_file->VdexBegin() != nullptr) {
    EXPECT_TRUE(DladdrIdentifies(odex_file->VdexBegin(), "oatdex"));
    EXPECT_TRUE(DladdrIdentifies(odex_file->VdexEnd() - sizeof(uint32_t), "oatdexlastword"));
  }
}

TEST_F(OatFileTest, RejectsCdex) {
  std::string dex_location = GetScratchDir() + "/LoadOat.jar";
  std::string odex_location = GetScratchDir() + "/LoadOat.odex";
  std::string vdex_location = GetVdexFilename(odex_location);

  Copy(GetDexSrc1(), dex_location);
  ASSERT_NO_FATAL_FAILURE(GenerateOdexForTest(dex_location, odex_location, CompilerFilter::kSpeed));

  // Patch the generated vdex file to simulate that it contains cdex.
  {
    size_t dex_offset;
    ASSERT_NO_FATAL_FAILURE(GetFirstDexFileOffset(vdex_location, &dex_offset));
    std::unique_ptr<File> vdex_file(OS::OpenFileReadWrite(vdex_location.c_str()));
    ASSERT_NE(vdex_file, nullptr) << strerror(errno);
    auto cleanup = android::base::make_scope_guard([&] { (void)vdex_file->FlushClose(); });
    constexpr std::string_view kCdexMagic = "cdex001\0"sv;
    ASSERT_LE(dex_offset + kCdexMagic.size(), vdex_file->GetLength()) << "Dex file too short";
    bool success = vdex_file->PwriteFully(kCdexMagic.data(), kCdexMagic.size(), dex_offset);
    ASSERT_TRUE(success) << strerror(errno);
    cleanup.Disable();
    ASSERT_EQ(vdex_file->FlushClose(), 0);
  }

  // Create `OatFile` from the vdex file together with the oat file. This should fail.
  {
    std::string error_msg;
    std::unique_ptr<OatFile> odex_file(OatFile::Open(/*zip_fd=*/-1,
                                                     odex_location,
                                                     odex_location,
                                                     /*executable=*/false,
                                                     /*low_4gb=*/false,
                                                     dex_location,
                                                     &error_msg));
    EXPECT_EQ(odex_file, nullptr) << "Cdex accepted unexpectedly";
    EXPECT_THAT(error_msg, HasSubstr("invalid dex file magic"));
  }

  // Create `OatFile` from the vdex file alone. This should fail too.
  {
    std::string error_msg;
    std::unique_ptr<VdexFile> vdex_file =
        VdexFile::Open(vdex_location, /*low_4gb=*/false, &error_msg);
    ASSERT_NE(vdex_file, nullptr);
    std::unique_ptr<OatFile> odex_file(OatFile::OpenFromVdex(/*zip_fd=*/-1,
                                                             std::move(vdex_file),
                                                             vdex_location,
                                                             /*context=*/nullptr,
                                                             kReasonVdex,
                                                             &error_msg));
    EXPECT_EQ(odex_file, nullptr) << "Cdex accepted unexpectedly";
    EXPECT_THAT(error_msg, HasSubstr("found dex file with invalid dex file version"));
  }
}

}  // namespace art HIDDEN

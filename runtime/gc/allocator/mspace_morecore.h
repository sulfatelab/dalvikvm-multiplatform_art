/*
 * Copyright (C) 2026 The Android Open Source Project
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

#ifndef ART_RUNTIME_GC_ALLOCATOR_MSPACE_MORECORE_H_
#define ART_RUNTIME_GC_ALLOCATOR_MSPACE_MORECORE_H_

#include <cstddef>
#include <cstdint>

namespace art {
namespace gc {
namespace allocator {

class MspaceMoreCoreProvider {
 public:
  virtual void* MoreCore(const void* mspace, intptr_t increment) = 0;

 protected:
  virtual ~MspaceMoreCoreProvider() = default;
};

// Creates an unlocked mspace in caller-owned storage. If provider is null, the
// caller must attach one before publishing the mspace or making an allocation.
void* ArtCreateMspaceWithBase(void* base,
                              size_t initial_footprint,
                              MspaceMoreCoreProvider* provider);

void ArtAttachMspaceMoreCoreProvider(void* mspace, MspaceMoreCoreProvider* provider);
void ArtDetachMspaceMoreCoreProvider(void* mspace, MspaceMoreCoreProvider* provider);

}  // namespace allocator
}  // namespace gc
}  // namespace art

#endif  // ART_RUNTIME_GC_ALLOCATOR_MSPACE_MORECORE_H_

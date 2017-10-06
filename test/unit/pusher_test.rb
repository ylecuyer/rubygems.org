require 'test_helper'

class PusherTest < ActiveSupport::TestCase
  context "creating a new gem" do
    setup do
      @user = create(:user, email: "user@example.com")
      @gem = gem_file
      @pusher = Pusher.new(@user, @gem)
    end

    should "have some state" do
      assert @pusher.respond_to?(:user)
      assert @pusher.respond_to?(:version)
      assert @pusher.respond_to?(:version_id)
      assert @pusher.respond_to?(:spec)
      assert @pusher.respond_to?(:message)
      assert @pusher.respond_to?(:code)
      assert @pusher.respond_to?(:rubygem)
      assert @pusher.respond_to?(:body)

      assert_equal @user, @pusher.user
    end

    should "initialize size from the gem" do
      assert_equal @gem.size, @pusher.size
    end

    context "processing incoming gems" do
      should "work normally when things go well" do
        @pusher.stubs(:pull_spec).returns true
        @pusher.stubs(:find).returns true
        @pusher.stubs(:authorize).returns true
        @pusher.stubs(:validate).returns true
        @pusher.stubs(:save)

        @pusher.process
      end

      should "not attempt to find rubygem if spec can't be pulled" do
        @pusher.stubs(:pull_spec).returns false
        @pusher.stubs(:find).never
        @pusher.stubs(:authorize).never
        @pusher.stubs(:save).never
        @pusher.process
      end

      should "not attempt to authorize if not found" do
        @pusher.stubs(:pull_spec).returns true
        @pusher.stubs(:find)
        @pusher.stubs(:authorize).never
        @pusher.stubs(:save).never

        @pusher.process
      end

      should "not attempt to validate if not authorized" do
        @pusher.stubs(:pull_spec).returns true
        @pusher.stubs(:find).returns true
        @pusher.stubs(:authorize).returns false
        @pusher.stubs(:validate).never
        @pusher.stubs(:save).never

        @pusher.process
      end

      should "not attempt to save if not validated" do
        @pusher.stubs(:pull_spec).returns true
        @pusher.stubs(:find).returns true
        @pusher.stubs(:authorize).returns true
        @pusher.stubs(:validate).returns false
        @pusher.stubs(:save).never

        @pusher.process
      end
    end

    should "not be able to pull spec from a bad path" do
      @pusher.stubs(:body).stubs(:stub!).stubs(:read)
      @pusher.pull_spec
      assert_nil @pusher.spec
      assert_match(/RubyGems\.org cannot process this gem/, @pusher.message)
      assert_equal @pusher.code, 422
    end

    should "not be able to pull spec with metadata containing bad ruby objects" do
      @gem = gem_file("exploit.gem")
      @pusher = Pusher.new(@user, @gem)
      @pusher.pull_spec
      assert_nil @pusher.spec
      assert_match(/RubyGems\.org cannot process this gem/, @pusher.message)
      assert_match(/ActionController::Routing::RouteSet::NamedRouteCollection/, @pusher.message)
      assert_equal @pusher.code, 422
    end

    should "not be able to save a gem if it is not valid" do
      legit_gem = create(:rubygem, name: 'legit-gem')
      create(:version, rubygem: legit_gem, number: '0.0.1')
      @gem = gem_file("legit-gem-0.0.1.gem.fake")
      @pusher = Pusher.new(@user, @gem)
      @pusher.stubs(:save).never
      @pusher.process
      assert_equal @pusher.rubygem.name, 'legit'
      assert_equal @pusher.version.number, 'gem-0.0.1'
      assert_match(/There was a problem saving your gem: Number is invalid/, @pusher.message)
      assert_equal @pusher.code, 403
    end

    should "not be able to pull spec with metadata containing bad ruby symbols" do
      ["1.0.0", "2.0.0", "3.0.0", "4.0.0"].each do |version|
        @gem = gem_file("dos-#{version}.gem")
        @pusher = Pusher.new(@user, @gem)
        @pusher.pull_spec
        assert_nil @pusher.spec
        assert_includes @pusher.message, %(RubyGems.org cannot process this gem)
        assert_includes @pusher.message, %(Tried to load unspecified class: Symbol)
        assert_equal @pusher.code, 422
      end
    end

    should "be able to pull spec with metadata containing aliases" do
      @gem = gem_file("aliases-0.0.0.gem")
      @pusher = Pusher.new(@user, @gem)
      @pusher.pull_spec
      assert_not_nil @pusher.spec
      assert_not_nil @pusher.spec.dependencies.first.requirement
    end

    should "not be able to pull spec when no data available" do
      @gem = gem_file("aliases-nodata-0.0.1.gem")
      @pusher = Pusher.new(@user, @gem)
      @pusher.pull_spec
      assert_includes @pusher.message, %{package content (data.tar.gz) is missing}
    end

    context "initialize new gem with find if one does not exist" do
      setup do
        spec = mock
        spec.expects(:name).returns "some name"
        spec.expects(:version).returns "1.3.3.7"
        spec.expects(:original_platform).returns "ruby"
        @pusher.stubs(:spec).returns spec
        @pusher.stubs(:size).returns 5
        @pusher.stubs(:body).returns StringIO.new("dummy body")

        @pusher.find
      end

      should "set rubygem" do
        assert_equal 'some name', @pusher.rubygem.name
      end

      should "set version" do
        assert_equal '1.3.3.7', @pusher.version.number
      end

      should "set gem version size" do
        assert_equal 5, @pusher.version.size
      end

      should "set sha256" do
        expected_sha = Digest::SHA2.base64digest(@pusher.body.string)
        assert_equal expected_sha, @pusher.version.sha256
      end
    end

    context "finding an existing gem" do
      should "bring up existing gem with matching spec" do
        @rubygem = create(:rubygem)
        spec = mock
        spec.stubs(:name).returns @rubygem.name
        spec.stubs(:version).returns "1.3.3.7"
        spec.stubs(:original_platform).returns "ruby"
        @pusher.stubs(:spec).returns spec
        @pusher.find

        assert_equal @rubygem, @pusher.rubygem
        assert_not_nil @pusher.version
      end

      should "error out when changing case with usuable versions" do
        @rubygem = create(:rubygem)
        create(:version, rubygem: @rubygem)

        assert_not_equal @rubygem.name, @rubygem.name.upcase

        spec = mock
        spec.expects(:name).returns @rubygem.name.upcase
        spec.expects(:version).returns "1.3.3.7"
        spec.expects(:original_platform).returns "ruby"
        @pusher.stubs(:spec).returns spec
        refute @pusher.find

        assert_match(/Unable to change case/, @pusher.message)
      end

      should "update the DB to reflect the case in the spec" do
        @rubygem = create(:rubygem)
        assert_not_equal @rubygem.name, @rubygem.name.upcase

        spec = mock
        spec.stubs(:name).returns @rubygem.name.upcase
        spec.stubs(:version).returns "1.3.3.7"
        spec.stubs(:original_platform).returns "ruby"
        @pusher.stubs(:spec).returns spec
        @pusher.find

        @pusher.rubygem.save
        @rubygem.reload

        assert_equal @rubygem.name, @rubygem.name.upcase
      end
    end

    context "checking if the rubygem can be pushed to" do
      should "be true if rubygem is new" do
        @pusher.stubs(:rubygem).returns Rubygem.new
        assert @pusher.authorize
      end

      context "with a existing rubygem" do
        setup do
          @rubygem = create(:rubygem, name: "the_gem_name")
          @pusher.stubs(:rubygem).returns @rubygem
        end

        should "be true if owned by the user" do
          @rubygem.ownerships.create(user: @user)
          assert @pusher.authorize
        end

        should "be true if no versions exist since it's a dependency" do
          assert @pusher.authorize
        end

        should "be false if not owned by user and an indexed version exists" do
          create(:version, rubygem: @rubygem, number: '0.1.1')
          refute @pusher.authorize
          assert_equal "You do not have permission to push to this gem. Ask an owner to add you with: gem owner the_gem_name --add user@example.com",
            @pusher.message
          assert_equal 403, @pusher.code
        end

        should "be true if not owned by user but no indexed versions exist" do
          create(:version, rubygem: @rubygem, number: '0.1.1', indexed: false)
          assert @pusher.authorize
        end
      end
    end

    context "successfully saving a gem" do
      setup do
        @rubygem = create(:rubygem, name: 'gemsgemsgems')
        @pusher.stubs(:rubygem).returns @rubygem
        create(:version, rubygem: @rubygem, number: '0.1.1', summary: 'old summary')
        @pusher.stubs(:version).returns @rubygem.versions[0]
        @rubygem.stubs(:update_attributes_from_gem_specification!)
        GemCachePurger.stubs(:call)
        Indexer.any_instance.stubs(:write_gem)
        @pusher.save
      end

      should "update rubygem attributes" do
        assert_received(@rubygem, :update_attributes_from_gem_specification!) do |rubygem|
          rubygem.with(@pusher.version, @pusher.spec)
        end
      end

      should "set gem file size" do
        assert_equal @gem.size, @pusher.size
      end

      should "set success code" do
        assert_equal 200, @pusher.code
      end

      should "set info_checksum" do
        assert_not_nil @rubygem.versions.last.info_checksum
      end

      should "call GemCachePurger" do
        assert_received(GemCachePurger, :call) { |obj| obj.with(@rubygem.name).once }
      end

      should "enque job for updating ES index, spec index and purging cdn" do
        assert_difference 'Delayed::Job.count', 2 do
          @pusher.save
        end
      end

      should "create rubygem index" do
        @rubygem.update_column('updated_at', Date.new(2016, 07, 04))
        Delayed::Worker.new.work_off
        response = Rubygem.__elasticsearch__.client.get index: "rubygems-#{Rails.env}",
                                                        type:  'rubygem',
                                                        id:    @rubygem.id
        expected_response = {
          'name'                  => 'gemsgemsgems',
          'yanked'                => false,
          'summary'               => 'old summary',
          'description'           => 'Some awesome gem',
          'downloads'             => 0,
          'latest_version_number' => '0.1.1',
          'updated'               => '2016-07-04T00:00:00.000Z'
        }

        assert_equal expected_response, response['_source']
      end
    end

    context 'pushing a new version' do
      setup do
        @rubygem = create(:rubygem)
        @pusher.stubs(:rubygem).returns @rubygem
        create(:version, rubygem: @rubygem, summary: 'old summary')
        version = create(:version, rubygem: @rubygem, summary: 'new summary')
        @pusher.stubs(:version).returns version
        @rubygem.stubs(:update_attributes_from_gem_specification!)
        @pusher.stubs(:version).returns version
        GemCachePurger.stubs(:call)
        Indexer.any_instance.stubs(:write_gem)
        @pusher.save
      end

      should "update rubygem index" do
        Delayed::Worker.new.work_off
        response = Rubygem.__elasticsearch__.client.get index: "rubygems-#{Rails.env}",
                                                        type:  'rubygem',
                                                        id:    @rubygem.id
        assert_equal 'new summary', response['_source']['summary']
      end
    end
  end
end
